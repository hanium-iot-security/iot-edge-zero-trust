"""READY pcap segment를 읽어 Packet Feature를 DB에 저장합니다."""

from __future__ import annotations

import argparse
import calendar
import contextlib
import fcntl
import ipaddress
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import SessionLocal
from edge.features.collect_feature_logs import parse_db_datetime
from edge.features.packet_feature_utils import (
    ParsedPacket,
    PcapParseError,
    build_ip_device_map,
    build_packet_features,
    parse_pcap,
    resolve_device_id,
)

logger = logging.getLogger(__name__)

CAPTURE_SCOPE_DEFAULT = "PI1_INTERNAL_LAN"
DEFAULT_READY_DIR = Path("data/pcap/ready")
DEFAULT_PROCESSED_DIR = Path("data/pcap/processed")
DEFAULT_FAILED_DIR = Path("data/pcap/failed")
DEFAULT_LIMIT = 10
DEFAULT_LOCK_PATH = Path("data/pcap/.extractor.lock")
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def _now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime(DATETIME_FORMAT)


@contextlib.contextmanager
def _acquire_lock(lock_path: Path):
    """fcntl.flock() 기반 단일 실행 보장 컨텍스트 매니저.

    이미 다른 프로세스가 lock을 보유 중이면 RuntimeError를 발생시킵니다.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(
                f"다른 extractor 프로세스가 실행 중입니다 ({lock_path})."
            )
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _move_pcap(src: Path, dst_dir: Path) -> None:
    """pcap 파일을 dst_dir로 이동합니다. 동명 파일이 있으면 덮어씁니다."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    if dst.exists():
        dst.unlink()
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
) -> int:
    """ready_dir 안 파일 중 DB 상태가 READY가 아닌 것을 올바른 디렉터리로 이동합니다.

    이전 실행에서 DB 커밋 후 파일 이동이 실패한 경우를 복구합니다.
    반환값: 실제로 이동한 파일 수.
    """
    if not ready_dir.exists():
        return 0
    moved = 0
    for pcap_file in sorted(ready_dir.glob("*.pcap")):
        row = db.execute(
            text(
                "SELECT status FROM packet_capture_segments WHERE file_name = :fname"
            ),
            {"fname": pcap_file.name},
        ).fetchone()
        if row is None:
            continue  # DB에 없는 파일: 무시
        status = row[0]
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
        except OSError:
            logger.error(
                "reconcile: %s 이동 실패, 다음 실행 시 재시도됩니다.", pcap_file.name
            )
    return moved


def _load_ip_device_map(db: Session) -> dict[str, str]:
    rows = db.execute(
        text(
            """
            SELECT device_id, ip_address
            FROM devices
            WHERE ip_address IS NOT NULL
              AND ip_address != ''
            """
        )
    ).mappings()
    return build_ip_device_map([dict(row) for row in rows])


def _fetch_ready_segments(db: Session, limit: int) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT id, file_name, window_start, window_end
            FROM packet_capture_segments
            WHERE status = 'READY'
            ORDER BY window_start, id
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).mappings()
    return [dict(row) for row in rows]


def _update_segment(
    db: Session,
    segment_id: int,
    *,
    status: str,
    packet_count: int | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    now = _now_utc_str()
    db.execute(
        text(
            """
            UPDATE packet_capture_segments
            SET status        = :status,
                packet_count  = :packet_count,
                processed_at  = :processed_at,
                error_code    = :error_code,
                error_message = :error_message,
                updated_at    = :updated_at
            WHERE id = :id
            """
        ),
        {
            "status": status,
            "packet_count": packet_count,
            "processed_at": now if status in ("PROCESSED", "EMPTY") else None,
            "error_code": error_code,
            "error_message": error_message,
            "updated_at": now,
            "id": segment_id,
        },
    )


def _insert_feature_rows(
    db: Session,
    segment_id: int,
    feature_rows: list[dict[str, Any]],
    ip_device_map: dict[str, str],
    capture_scope: str,
) -> None:
    for row in feature_rows:
        device_id = resolve_device_id(row["peer_ip"], ip_device_map)
        # ON CONFLICT DO NOTHING: (capture_segment_id, peer_ip, direction) 중복만 무시.
        # NOT NULL / CHECK 위반은 예외로 전파해 transaction 전체를 rollback합니다.
        db.execute(
            text(
                """
                INSERT INTO packet_feature_logs (
                    capture_segment_id,
                    device_id,
                    peer_ip,
                    direction,
                    window_start,
                    window_end,
                    packet_count,
                    total_bytes,
                    avg_packet_size,
                    max_packet_size,
                    mean_inter_arrival_time,
                    distinct_dest_port_count,
                    tcp_syn_count,
                    mqtt_related_packet_count,
                    non_mqtt_tcp_udp_packet_count,
                    capture_scope
                )
                VALUES (
                    :capture_segment_id,
                    :device_id,
                    :peer_ip,
                    :direction,
                    :window_start,
                    :window_end,
                    :packet_count,
                    :total_bytes,
                    :avg_packet_size,
                    :max_packet_size,
                    :mean_inter_arrival_time,
                    :distinct_dest_port_count,
                    :tcp_syn_count,
                    :mqtt_related_packet_count,
                    :non_mqtt_tcp_udp_packet_count,
                    :capture_scope
                )
                ON CONFLICT(capture_segment_id, peer_ip, direction) DO NOTHING
                """
            ),
            {
                "capture_segment_id": segment_id,
                "device_id": device_id,
                "peer_ip": row["peer_ip"],
                "direction": row["direction"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "packet_count": row["packet_count"],
                "total_bytes": row["total_bytes"],
                "avg_packet_size": row["avg_packet_size"],
                "max_packet_size": row["max_packet_size"],
                "mean_inter_arrival_time": row["mean_inter_arrival_time"],
                "distinct_dest_port_count": row["distinct_dest_port_count"],
                "tcp_syn_count": row["tcp_syn_count"],
                "mqtt_related_packet_count": row["mqtt_related_packet_count"],
                "non_mqtt_tcp_udp_packet_count": row["non_mqtt_tcp_udp_packet_count"],
                "capture_scope": capture_scope,
            },
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
) -> int:
    """READY segment를 limit 개까지 처리하고 처리 시도 수를 반환합니다."""
    pi_ip = settings.capture_interface_ip
    if not pi_ip:
        raise ValueError("CAPTURE_INTERFACE_IP가 설정되지 않았습니다.")
    _validate_ip(pi_ip)

    with _acquire_lock(lock_path):
        with SessionLocal() as db:
            # 이전 실행에서 커밋 후 이동 실패한 파일을 먼저 복구
            reconcile_orphaned_files(db, ready_dir, processed_dir, failed_dir)
            ip_device_map = _load_ip_device_map(db)
            segments = _fetch_ready_segments(db, limit)

        count = 0
        for segment in segments:
            pcap_path = ready_dir / segment["file_name"]

            # DB 처리 예외와 파일 이동 예외를 분리
            try:
                with SessionLocal() as db:
                    status = process_segment(
                        db, segment, ready_dir, pi_ip, ip_device_map, capture_scope
                    )
            except Exception:
                logger.exception(
                    "DB 오류로 segment_id=%d 처리 실패, READY 유지", segment["id"]
                )
                continue

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
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--capture-scope", type=str, default=CAPTURE_SCOPE_DEFAULT)
    parser.add_argument("--lock-path", type=Path, default=DEFAULT_LOCK_PATH)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    count = extract_packet_features(
        ready_dir=args.ready_dir,
        processed_dir=args.processed_dir,
        failed_dir=args.failed_dir,
        limit=args.limit,
        capture_scope=args.capture_scope,
        lock_path=args.lock_path,
    )
    print(f"처리 완료: {count} segments")


if __name__ == "__main__":
    main()
