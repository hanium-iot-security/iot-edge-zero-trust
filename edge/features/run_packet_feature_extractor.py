"""READY pcap segment를 읽어 Packet Feature를 DB에 저장합니다."""

from __future__ import annotations

import argparse
import calendar
import contextlib
import hashlib
import ipaddress
import logging
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import fcntl as _fcntl
    _HAS_FCNTL = True
except ImportError:
    _fcntl = None  # type: ignore[assignment]
    _HAS_FCNTL = False

from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import SessionLocal
from edge.features.collect_feature_logs import parse_db_datetime
from edge.features.packet_feature_repository import (
    fetch_ready_segments,
    get_segment_status_by_file_name,
    insert_packet_feature_rows,
    load_ip_device_map,
    update_capture_segment_status,
)
from edge.features.packet_feature_utils import (
    ParsedPacket,
    PartialPcapError,
    PcapParseError,
    UnsupportedPcapFormat,
    build_packet_features,
    parse_pcap,
)
from edge.packet.capture_session_repository import get_capture_session_by_session_id

logger = logging.getLogger(__name__)

CAPTURE_SCOPE_DEFAULT = "PI1_INTERNAL_LAN"
DEFAULT_READY_DIR = Path("data/pcap/ready")
DEFAULT_PROCESSED_DIR = Path("data/pcap/processed")
DEFAULT_FAILED_DIR = Path("data/pcap/failed")
DEFAULT_LIMIT = 10
DEFAULT_LOCK_PATH = Path("data/pcap/.extractor.lock")


class ExtractorPreflightError(ValueError):
    """Extractor가 DB나 PCAP을 변경하기 전에 발견한 실행 조건 오류."""


@contextlib.contextmanager
def _acquire_lock(lock_path: Path):
    """fcntl.flock() 기반 단일 실행 보장 컨텍스트 매니저.

    이미 다른 프로세스가 lock을 보유 중이면 RuntimeError를 발생시킵니다.
    Windows 등 fcntl 미지원 환경에서는 경고 후 lock 없이 실행합니다.
    """
    if not _HAS_FCNTL:
        logger.warning("fcntl 미지원 환경: Lock 없이 실행합니다 (운영 환경에서는 Pi만 사용하세요).")
        yield
        return
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_file:
        try:
            _fcntl.flock(lock_file.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(
                f"다른 extractor 프로세스가 실행 중입니다 ({lock_path})."
            )
        try:
            yield
        finally:
            _fcntl.flock(lock_file.fileno(), _fcntl.LOCK_UN)


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _move_pcap(src: Path, dst_dir: Path) -> None:
    """pcap 파일을 dst_dir로 이동합니다.

    동명 파일이 이미 존재할 때:
    - 내용이 같으면: src만 삭제 (중복 제거)
    - 내용이 다르면: FileExistsError를 발생시켜 기존 파일을 보존합니다.
    """
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    if dst.exists():
        if _file_sha256(src) == _file_sha256(dst):
            src.unlink()
            return
        raise FileExistsError(
            f"동명 파일이 이미 존재하며 내용이 다릅니다: {dst}. 기존 파일을 보존합니다."
        )
    shutil.move(str(src), dst)


def _any_in_window(
    packets: list[ParsedPacket],
    window_start: datetime,
    window_end: datetime,
) -> bool:
    """packets 중 하나라도 [window_start, window_end) 범위에 있으면 True."""
    ws = float(calendar.timegm(window_start.timetuple()))
    we = float(calendar.timegm(window_end.timetuple()))
    return any(ws <= pkt.timestamp < we for pkt in packets)


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError(
            f"CAPTURE_INTERFACE_IP가 올바른 IPv4 형식이 아닙니다: {ip!r}"
        )


def reconcile_orphaned_files(
    db: Session,
    ready_dir: Path,
    processed_dir: Path,
    failed_dir: Path,
    *,
    session_id: str | None = None,
) -> int:
    """ready_dir 안 파일 중 DB 상태가 READY가 아닌 것을 올바른 디렉터리로 이동합니다.

    이전 실행에서 DB 커밋 후 파일 이동이 실패한 경우를 복구합니다.
    반환값: 실제로 이동한 파일 수.
    """
    if not ready_dir.exists():
        return 0
    moved = 0
    for pcap_file in sorted(ready_dir.glob("*.pcap")):
        status = get_segment_status_by_file_name(
            db,
            file_name=pcap_file.name,
            session_id=session_id,
        )
        if status is None:
            continue  # DB에 없는 파일: 무시
        try:
            if status in ("PROCESSED", "EMPTY"):
                _move_pcap(pcap_file, processed_dir)
                moved += 1
                logger.info("reconcile: %s → processed/", pcap_file.name)
            elif status == "FAILED":
                _move_pcap(pcap_file, failed_dir)
                moved += 1
                logger.info("reconcile: %s → failed/", pcap_file.name)
            # READY: 건드리지 않음
        except FileExistsError:
            logger.error(
                "reconcile: %s 충돌 — 동명 파일의 내용이 다릅니다. "
                "수동 조치가 필요합니다 (자동 복구 불가).",
                pcap_file.name,
            )
        except OSError:
            logger.error(
                "reconcile: %s 이동 실패, 다음 실행 시 재시도됩니다.", pcap_file.name
            )
    return moved


def _load_ip_device_map(db: Session) -> dict[str, str]:
    return load_ip_device_map(db)


def _fetch_ready_segments(
    db: Session,
    limit: int,
    *,
    session_id: str | None = None,
) -> list[dict[str, Any]]:
    return fetch_ready_segments(db, limit=limit, session_id=session_id)


def _validate_session_id(session_id: str) -> str:
    try:
        parsed = UUID(session_id)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExtractorPreflightError(
            f"--session-id는 canonical UUIDv4 형식이어야 합니다: {session_id!r}"
        ) from exc
    if parsed.version != 4 or str(parsed) != session_id:
        raise ExtractorPreflightError(
            f"--session-id는 canonical UUIDv4 형식이어야 합니다: {session_id!r}"
        )
    return session_id


def _require_completed_capture_session(db: Session, session_id: str) -> None:
    capture_session = get_capture_session_by_session_id(db, session_id=session_id)
    if capture_session is None:
        raise ExtractorPreflightError(
            f"Capture Session이 존재하지 않습니다: session_id={session_id}"
        )
    status = str(capture_session["status"])
    if status != "COMPLETED":
        raise ExtractorPreflightError(
            "--session-id 모드는 COMPLETED Capture Session만 처리합니다: "
            f"session_id={session_id}, status={status}"
        )


def _update_segment(
    db: Session,
    segment_id: int,
    *,
    status: str,
    packet_count: int | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    update_capture_segment_status(
        db,
        segment_id=segment_id,
        status=status,
        packet_count=packet_count,
        error_code=error_code,
        error_message=error_message,
    )


def _insert_feature_rows(
    db: Session,
    segment_id: int,
    feature_rows: list[dict[str, Any]],
    ip_device_map: dict[str, str],
    capture_scope: str,
) -> None:
    insert_packet_feature_rows(
        db,
        capture_segment_id=segment_id,
        feature_rows=feature_rows,
        ip_device_map=ip_device_map,
        capture_scope=capture_scope,
    )


def process_segment(
    db: Session,
    segment: dict[str, Any],
    ready_dir: Path,
    pi_ip: str,
    ip_device_map: dict[str, str],
    capture_scope: str = CAPTURE_SCOPE_DEFAULT,
) -> str:
    """READY segment 하나를 처리하고 최종 status를 반환합니다.

    성공/영구 실패(PROCESSED, EMPTY, FAILED): db.commit() 후 반환.
    DB 오류: 예외를 전파. caller가 rollback 처리.
    """
    segment_id = int(segment["id"])
    pcap_path = ready_dir / segment["file_name"]
    window_start = parse_db_datetime(segment["window_start"])
    window_end = parse_db_datetime(segment["window_end"])

    try:
        packets = parse_pcap(pcap_path)
    except FileNotFoundError as exc:
        _update_segment(
            db, segment_id,
            status="FAILED",
            error_code="PCAP_FILE_MISSING",
            error_message=str(exc),
        )
        db.commit()
        logger.warning("PCAP_FILE_MISSING segment_id=%d file=%s", segment_id, pcap_path)
        return "FAILED"
    except PartialPcapError as exc:
        _update_segment(
            db, segment_id,
            status="FAILED",
            error_code="PARTIAL_CAPTURE",
            error_message=str(exc),
        )
        db.commit()
        logger.warning("PARTIAL_CAPTURE segment_id=%d file=%s", segment_id, pcap_path)
        return "FAILED"
    except UnsupportedPcapFormat as exc:
        _update_segment(
            db, segment_id,
            status="FAILED",
            error_code="UNSUPPORTED_FORMAT",
            error_message=str(exc),
        )
        db.commit()
        logger.warning("UNSUPPORTED_FORMAT segment_id=%d file=%s", segment_id, pcap_path)
        return "FAILED"
    except PcapParseError as exc:
        _update_segment(
            db, segment_id,
            status="FAILED",
            error_code="PCAP_PARSE_ERROR",
            error_message=str(exc),
        )
        db.commit()
        logger.warning("PCAP_PARSE_ERROR segment_id=%d file=%s", segment_id, pcap_path)
        return "FAILED"

    packet_count = len(packets)
    feature_rows = build_packet_features(packets, pi_ip, window_start, window_end)

    if not feature_rows:
        # 패킷이 존재하지만 모두 window 범위 밖: 잘못된 pcap 파일 할당
        if packet_count > 0 and not _any_in_window(packets, window_start, window_end):
            _update_segment(
                db, segment_id,
                status="FAILED",
                error_code="WINDOW_MISMATCH",
                error_message="pcap 내 패킷이 모두 segment window 범위 밖에 있습니다.",
            )
            db.commit()
            logger.warning("WINDOW_MISMATCH segment_id=%d file=%s", segment_id, pcap_path)
            return "FAILED"
        # window 내 패킷이 없거나 Pi 관련 트래픽 없음
        _update_segment(db, segment_id, status="EMPTY", packet_count=packet_count)
        db.commit()
        return "EMPTY"

    _insert_feature_rows(db, segment_id, feature_rows, ip_device_map, capture_scope)
    _update_segment(db, segment_id, status="PROCESSED", packet_count=packet_count)
    db.commit()
    return "PROCESSED"


def extract_packet_features(
    ready_dir: Path = DEFAULT_READY_DIR,
    processed_dir: Path = DEFAULT_PROCESSED_DIR,
    failed_dir: Path = DEFAULT_FAILED_DIR,
    limit: int = DEFAULT_LIMIT,
    capture_scope: str = CAPTURE_SCOPE_DEFAULT,
    lock_path: Path = DEFAULT_LOCK_PATH,
    session_id: str | None = None,
) -> int:
    """READY segment를 limit 개까지 처리하고 처리 시도 수를 반환합니다."""
    if limit < 1:
        raise ExtractorPreflightError(f"--limit은 1 이상이어야 합니다: {limit}")
    selected_session_id = (
        _validate_session_id(session_id) if session_id is not None else None
    )
    pi_ip = settings.capture_interface_ip
    if not pi_ip:
        raise ValueError("CAPTURE_INTERFACE_IP가 설정되지 않았습니다.")
    _validate_ip(pi_ip)

    with _acquire_lock(lock_path):
        with SessionLocal() as db:
            if selected_session_id is None:
                logger.warning(
                    "--session-id 미지정: 모든 Capture Session의 전체 READY backlog와 "
                    "전역 Reconciliation을 처리합니다."
                )
            else:
                _require_completed_capture_session(db, selected_session_id)
            # 이전 실행에서 커밋 후 이동 실패한 파일을 먼저 복구
            reconcile_orphaned_files(
                db,
                ready_dir,
                processed_dir,
                failed_dir,
                session_id=selected_session_id,
            )
            ip_device_map = _load_ip_device_map(db)
            segments = _fetch_ready_segments(
                db,
                limit,
                session_id=selected_session_id,
            )

        count = 0
        for segment in segments:
            pcap_path = ready_dir / segment["file_name"]

            # DB 처리 예외와 파일 이동 예외를 분리
            try:
                with SessionLocal() as db:
                    status = process_segment(
                        db, segment, ready_dir, pi_ip, ip_device_map, capture_scope
                    )
            except OperationalError as exc:
                err_lower = str(exc).lower()
                if "locked" in err_lower or "busy" in err_lower:
                    # SQLite database is locked/busy: 일시적 경합, READY 유지 후 재시도
                    logger.exception(
                        "DB 잠금/연결 오류로 segment_id=%d 처리 실패, READY 유지", segment["id"]
                    )
                    continue
                # 테이블 누락, 디스크 오류 등 복구 불가능한 OperationalError: 상위로 전파
                logger.exception(
                    "복구 불가능한 OperationalError로 segment_id=%d 처리 중단", segment["id"]
                )
                raise
            except SQLAlchemyError:
                # IntegrityError, ProgrammingError 등 구조적 DB 오류: 상위로 전파
                logger.exception(
                    "복구 불가능한 DB 오류로 segment_id=%d 처리 중단", segment["id"]
                )
                raise
            except Exception:
                logger.exception(
                    "예상하지 못한 오류로 segment_id=%d 처리 중단", segment["id"]
                )
                raise

            # DB 커밋 성공 후 파일 이동 실패는 별도 로그 (다음 실행 시 reconcile이 복구)
            try:
                if status in ("PROCESSED", "EMPTY") and pcap_path.exists():
                    _move_pcap(pcap_path, processed_dir)
                elif status == "FAILED" and pcap_path.exists():
                    _move_pcap(pcap_path, failed_dir)
            except OSError:
                logger.error(
                    "파일 이동 실패 segment_id=%d file=%s status=%s. "
                    "다음 실행 시 reconcile로 복구됩니다.",
                    segment["id"], pcap_path.name, status,
                )
            count += 1

    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="READY pcap segment를 Packet Feature로 변환합니다."
    )
    parser.add_argument("--ready-dir", type=Path, default=DEFAULT_READY_DIR)
    parser.add_argument("--processed-dir", type=Path, default=DEFAULT_PROCESSED_DIR)
    parser.add_argument("--failed-dir", type=Path, default=DEFAULT_FAILED_DIR)
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="처리할 COMPLETED Capture Session의 canonical UUIDv4",
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--capture-scope", type=str, default=CAPTURE_SCOPE_DEFAULT)
    parser.add_argument("--lock-path", type=Path, default=DEFAULT_LOCK_PATH)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        count = extract_packet_features(
            ready_dir=args.ready_dir,
            processed_dir=args.processed_dir,
            failed_dir=args.failed_dir,
            limit=args.limit,
            capture_scope=args.capture_scope,
            lock_path=args.lock_path,
            session_id=args.session_id,
        )
    except ExtractorPreflightError as exc:
        parser.error(str(exc))
    print(f"처리 완료: {count} segments")


if __name__ == "__main__":
    main()
