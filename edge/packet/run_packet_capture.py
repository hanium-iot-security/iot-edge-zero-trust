"""Packet Capture Runtime 진입점.

전체 흐름: Crash Recovery -> Session 생성 -> Gap 기록 -> 10초 Window 반복 캡처.
systemd(packet-capture.service)가 이 모듈을 기동/재시작합니다.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import signal
import sys
import time
from typing import Callable
import uuid

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy.orm import Session

from backend.app.database import SessionLocal
from edge.packet import capture_session_repository as repo
from edge.packet.capture_runtime import (
    LATE_CAPTURE,
    CaptureProcess,
    CaptureRuntimeConfig,
    TcpdumpCaptureProcess,
    execute_capture_window,
)
from edge.packet.pcap_naming import format_utc_iso, next_utc_boundary, parse_pcap_filename

logger = logging.getLogger(__name__)


class GracefulShutdown:
    """SIGTERM/SIGINT 수신 시 현재 Window 작업을 끝까지 마친 뒤 루프를 빠져나가게 합니다.

    관리자가 `systemctl stop`으로 정상 중지한 경우 프로세스는 exit code 0으로
    종료되므로 Restart=on-failure가 재시작을 트리거하지 않습니다.
    """

    def __init__(self) -> None:
        self.requested = False

    def request(self, signum, _frame) -> None:
        logger.info("Shutdown signal received (signum=%s); finishing current window then exiting", signum)
        self.requested = True

    def install(self) -> None:
        signal.signal(signal.SIGTERM, self.request)
        signal.signal(signal.SIGINT, self.request)


def reconcile_leftover_tmp_files(db: Session, config: CaptureRuntimeConfig) -> int:
    """재시작 시 incoming에 남은 .pcap.tmp를 PARTIAL_CAPTURE로 확정합니다.

    정상 Feature로 사용하지 않고 failed 디렉터리로 옮긴 뒤 FAILED Segment row를 남깁니다.
    """
    reconciled = 0
    for tmp_path in sorted(config.incoming_dir.glob("*.pcap.tmp")):
        parsed = parse_pcap_filename(tmp_path.name)
        if parsed is None:
            logger.warning("incoming에 이름 규칙에 맞지 않는 파일 발견, 건드리지 않음: %s", tmp_path.name)
            continue

        ready_filename = tmp_path.name[: -len(".tmp")]
        tmp_path.replace(config.failed_dir / ready_filename)

        session_pk = repo.find_session_pk_by_session_id(db, parsed.session_id)
        if session_pk is None:
            logger.warning(
                "leftover .pcap.tmp의 session_id를 DB에서 찾지 못해 파일만 이동함: %s",
                tmp_path.name,
            )
            continue

        if repo.find_segment_by_file_name(db, ready_filename) is not None:
            continue

        repo.insert_failed_segment(
            db,
            capture_session_pk=session_pk,
            file_name=ready_filename,
            capture_interface=parsed.interface,
            window_start=parsed.window_start,
            window_end=parsed.window_end,
            error_code=repo.PARTIAL_CAPTURE,
            error_message="leftover .pcap.tmp found in incoming/ on service restart",
        )
        reconciled += 1
        logger.info("Partial Capture로 확정: %s", ready_filename)

    if reconciled:
        db.commit()
    return reconciled


def reconcile_orphan_ready_files(db: Session, config: CaptureRuntimeConfig) -> int:
    """ready/에는 있지만 Segment row가 없는 파일에 대해 READY row를 복구합니다 (3.4 절)."""
    reconciled = 0
    for ready_path in sorted(config.ready_dir.glob("*.pcap")):
        if repo.find_segment_by_file_name(db, ready_path.name) is not None:
            continue

        parsed = parse_pcap_filename(ready_path.name)
        if parsed is None:
            logger.warning("ready에 이름 규칙에 맞지 않는 파일 발견, 건드리지 않음: %s", ready_path.name)
            continue

        session_pk = repo.find_session_pk_by_session_id(db, parsed.session_id)
        if session_pk is None:
            logger.warning(
                "orphan ready 파일의 session_id를 DB에서 찾지 못해 READY row를 복구하지 못함: %s",
                ready_path.name,
            )
            continue

        repo.insert_ready_segment(
            db,
            capture_session_pk=session_pk,
            file_name=ready_path.name,
            capture_interface=parsed.interface,
            window_start=parsed.window_start,
            window_end=parsed.window_end,
        )
        reconciled += 1
        logger.info("orphan ready 파일에 대해 READY row 복구: %s", ready_path.name)

    if reconciled:
        db.commit()
    return reconciled


def reconcile_orphan_failed_files(db: Session, config: CaptureRuntimeConfig) -> int:
    """failed/에는 있지만 Segment row가 없는 파일에 대해 FAILED row를 복구합니다.

    파일을 failed/로 옮긴 뒤 DB 저장(insert_failed_segment)이 실패하거나, 그 사이에
    프로세스가 죽으면 파일만 있고 row가 없는 상태가 남을 수 있다 (7 번 리뷰 항목).
    reconcile_orphan_ready_files와 대칭적인 복구 로직이다.
    """
    reconciled = 0
    for failed_path in sorted(config.failed_dir.glob("*.pcap")):
        if repo.find_segment_by_file_name(db, failed_path.name) is not None:
            continue

        parsed = parse_pcap_filename(failed_path.name)
        if parsed is None:
            logger.warning("failed에 이름 규칙에 맞지 않는 파일 발견, 건드리지 않음: %s", failed_path.name)
            continue

        session_pk = repo.find_session_pk_by_session_id(db, parsed.session_id)
        if session_pk is None:
            logger.warning(
                "orphan failed 파일의 session_id를 DB에서 찾지 못해 FAILED row를 복구하지 못함: %s",
                failed_path.name,
            )
            continue

        repo.insert_failed_segment(
            db,
            capture_session_pk=session_pk,
            file_name=failed_path.name,
            capture_interface=parsed.interface,
            window_start=parsed.window_start,
            window_end=parsed.window_end,
            error_code=repo.PARTIAL_CAPTURE,
            error_message="orphan failed file recovered on restart: file existed without a Segment row",
        )
        reconciled += 1
        logger.info("orphan failed 파일에 대해 FAILED row 복구: %s", failed_path.name)

    if reconciled:
        db.commit()
    return reconciled


def reconcile_stale_running_sessions(db: Session, config: CaptureRuntimeConfig, now: datetime) -> int:
    """서비스가 비정상 종료되어 RUNNING 상태로 남아있는 이전 Session을 FAILED로 마감합니다.

    새 Session을 생성하기 전에 호출해야 합니다 (5 번 리뷰 항목).
    """
    reconciled = repo.close_stale_running_sessions(db, config.capture_interface, now)
    if reconciled:
        db.commit()
        logger.warning("비정상 종료로 남아있던 RUNNING Session %d개를 FAILED로 마감함", reconciled)
    return reconciled


def start_new_session(
    db: Session,
    config: CaptureRuntimeConfig,
    now: datetime,
    *,
    fallback_gap_start: datetime | None = None,
) -> tuple[int, str, datetime]:
    """새 Session을 생성하고 first_window_start·Capture Gap을 기록합니다.

    fallback_gap_start: 이 interface에 대해 DB에 기록된 Segment가 전혀 없을 때
    Gap 시작점으로 사용할 값입니다. 만료된 Window로 인해 Session이 전환되는 경우,
    놓친 window_start를 여기로 넘기면 "이전 Segment가 하나도 없어 Gap을 계산 못 하는" 상황에서도 공백이 누락되지 않습니다.

    Returns:
        (session_pk, session_id, first_window_start)
    """
    session_id = str(uuid.uuid4())
    session_pk = repo.create_session(
        db,
        session_id=session_id,
        capture_interface=config.capture_interface,
        started_at=now,
    )

    first_window_start = next_utc_boundary(now, config.window_seconds)
    repo.set_first_window_start(db, session_pk, first_window_start)

    previous_window_end = repo.find_last_segment_window_end(db, config.capture_interface)
    if previous_window_end is None:
        previous_window_end = fallback_gap_start
    if previous_window_end is not None and previous_window_end < first_window_start:
        repo.record_capture_gap(db, session_pk, previous_window_end, first_window_start)
        logger.info(
            "Capture Gap 기록: %s ~ %s (interface=%s)",
            format_utc_iso(previous_window_end), format_utc_iso(first_window_start), config.capture_interface,
        )

    db.commit()
    logger.info(
        "새 Capture Session 시작: session_id=%s first_window_start=%s",
        session_id, format_utc_iso(first_window_start),
    )
    return session_pk, session_id, first_window_start


def run_capture_loop(
    db: Session,
    process: CaptureProcess,
    config: CaptureRuntimeConfig,
    *,
    session_pk: int,
    session_id: str,
    first_window_start: datetime,
    shutdown: GracefulShutdown,
    max_windows: int | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """first_window_start부터 연속으로 10초 Window를 캡처합니다.

    Window 경계(window_start)까지 대기한 뒤 캡처를 시작하고, execute_capture_window가
    Phase 4 Capture Policy(허용 지연·최소 Duration)에 따라 LATE_CAPTURE 여부를 판정합니다.

    허용 지연을 초과해 LATE_CAPTURE로 판정되면(Window 대기 중 만료 포함) 감사용
    FAILED/LATE_CAPTURE Segment 한 건만 남기고 현재 Session을 FAILED로 마감한 뒤
    다음 정수 경계에서 새 Session을 시작합니다. 서비스 시작·재시작 시점에 이미 여러 과거 Window가 지나있는 경우는 
    start_new_session의 Session Gap 기록으로 처리되며, 여기서는 Window별 가짜 Segment를 소급 생성하지 않습니다.

    max_windows가 주어지면 그만큼만 캡처하고 반환합니다 (수동 테스트/`--windows` 옵션용).
    max_windows 카운트에는 LATE_CAPTURE로 건너뛴 Window는 포함하지 않습니다.

    Returns:
        실제로 캡처를 시도한(READY 또는 PARTIAL_CAPTURE) Window 개수.
    """
    window_start = first_window_start
    windows_captured = 0

    def _close_current_session(now: datetime, status: str) -> None:
        repo.close_session(db, session_pk, now, status)
        db.commit()

    def _record_late_capture_and_transition(
        now: datetime,
        *,
        missed_window_end: datetime,
        start_delay_seconds: float | None,
        error_message: str,
    ) -> None:
        """허용 지연 초과 Window 한 건을 감사용 Segment로 남기고 새 Session으로 전환한다."""
        nonlocal session_pk, session_id, window_start
        missed_window_start = window_start
        repo.insert_late_capture_segment(
            db,
            capture_session_pk=session_pk,
            capture_interface=config.capture_interface,
            window_start=missed_window_start,
            window_end=missed_window_end,
            error_message=error_message,
            start_delay_seconds=start_delay_seconds,
        )
        db.commit()
        logger.warning(
            "LATE_CAPTURE segment 생성: window=%s~%s start_delay_seconds=%s; "
            "Session을 FAILED로 마감하고 다음 경계에서 새 Session으로 전환",
            format_utc_iso(missed_window_start), format_utc_iso(missed_window_end),
            start_delay_seconds,
        )
        # 허용 지연을 초과한 Window는 ... 부모 packet_capture_sessions.status=FAILED로
        # 마감한다. (COMPLETED가 아니라 FAILED로 마감해야 Phase 4 Cutover/모니터링에서
        # 지연으로 인한 전환과 정상 종료를 구분할 수 있다.)
        _close_current_session(now, "FAILED")
        session_pk, session_id, window_start = start_new_session(
            db, config, now, fallback_gap_start=missed_window_end
        )

    try:
        while not shutdown.requested:
            now = clock()
            window_end = window_start + timedelta(seconds=config.window_seconds)

            if window_end > now:
                _sleep_until(window_start, clock=clock, sleep=sleep)
                if shutdown.requested:
                    # 대기 중 종료 신호를 받았다면 새 캡처를 시작하지 않고 즉시 빠져나간다
                    break

            capture_started_at = clock()

            drift_seconds = (capture_started_at - window_start).total_seconds()
            allowed_delay = config.capture_policy.max_start_delay_seconds + config.capture_policy.epsilon_seconds
            if 0 < drift_seconds <= allowed_delay:
                # 허용 범위 안의 지연이다 -- execute_capture_window가 window_end까지
                # 남은 시간만큼만 캡처하도록 자체 보정하므로 다음 Window로 누적되지
                # 않는다. 다만 지속 관측되면 DB/디스크 성능 저하의 신호일 수 있어 로그로 남긴다.
                logger.info(
                    "Window %s 캡처가 %.3fs 지연되어 시작됨 (자동 보정됨)",
                    format_utc_iso(window_start), drift_seconds,
                )

            result = execute_capture_window(
                process,
                config,
                session_id=session_id,
                window_start=window_start,
                window_end=window_end,
                capture_started_at=capture_started_at,
                policy=config.capture_policy,
                clock=clock,
            )

            if result.error_code == LATE_CAPTURE:
                _record_late_capture_and_transition(
                    capture_started_at,
                    missed_window_end=window_end,
                    start_delay_seconds=result.start_delay_seconds,
                    error_message=result.error_message or "",
                )
                continue

            if result.success:
                repo.insert_ready_segment(
                    db,
                    capture_session_pk=session_pk,
                    file_name=result.file_name,
                    capture_interface=config.capture_interface,
                    window_start=window_start,
                    window_end=window_end,
                    actual_capture_started_at=result.actual_capture_started_at,
                    capture_stop_requested_at=result.capture_stop_requested_at,
                    capture_process_exited_at=result.capture_process_exited_at,
                    start_delay_seconds=result.start_delay_seconds,
                    captured_duration_seconds=result.captured_duration_seconds,
                )
                logger.info("READY segment 생성: %s", result.file_name)
            else:
                repo.insert_failed_segment(
                    db,
                    capture_session_pk=session_pk,
                    file_name=result.file_name,
                    capture_interface=config.capture_interface,
                    window_start=window_start,
                    window_end=window_end,
                    error_code=result.error_code or repo.PARTIAL_CAPTURE,
                    error_message=result.error_message or "",
                    actual_capture_started_at=result.actual_capture_started_at,
                    capture_stop_requested_at=result.capture_stop_requested_at,
                    capture_process_exited_at=result.capture_process_exited_at,
                    start_delay_seconds=result.start_delay_seconds,
                    captured_duration_seconds=result.captured_duration_seconds,
                )
                logger.warning("FAILED segment 생성: %s (%s)", result.file_name, result.error_code)

            db.commit()
            window_start = window_end
            windows_captured += 1

            if max_windows is not None and windows_captured >= max_windows:
                break
    except Exception:
        logger.exception("Capture loop failed unexpectedly; marking current session FAILED")
        try:
            db.rollback()
            _close_current_session(clock(), "FAILED")
        except Exception:
            logger.exception(
                "Session을 FAILED로 마감하는 cleanup 자체가 실패함 (원래 예외는 위 로그 참고)"
            )
        raise  # non-zero exit -> systemd Restart=on-failure

    _close_current_session(clock(), "COMPLETED")
    return windows_captured


def _sleep_until(
    target: datetime,
    *,
    clock: Callable[[], datetime],
    sleep: Callable[[float], None],
) -> None:
    remaining = (target - clock()).total_seconds()
    if remaining > 0:
        sleep(remaining)


def main() -> None:
    parser = argparse.ArgumentParser(description="Raspberry Pi #1 Packet Capture Runtime")
    parser.add_argument(
        "--windows",
        type=int,
        default=None,
        help="캡처할 Window 개수 (미지정 시 무한 반복). 수동 검증 시 예: --windows 1",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = CaptureRuntimeConfig.from_env()
    config.ensure_directories()
    process = TcpdumpCaptureProcess(
        tcpdump_path=config.tcpdump_path,
        capture_filter=config.capture_filter,
    )

    shutdown = GracefulShutdown()
    shutdown.install()

    with SessionLocal() as db:
        reconcile_leftover_tmp_files(db, config)
        reconcile_orphan_ready_files(db, config)
        reconcile_orphan_failed_files(db, config)

        now = datetime.now(timezone.utc)
        reconcile_stale_running_sessions(db, config, now)
        session_pk, session_id, first_window_start = start_new_session(db, config, now)

        windows_captured = run_capture_loop(
            db,
            process,
            config,
            session_pk=session_pk,
            session_id=session_id,
            first_window_start=first_window_start,
            shutdown=shutdown,
            max_windows=args.windows,
        )
        logger.info("Capture Runtime 종료: windows_captured=%d", windows_captured)


if __name__ == "__main__":
    main()
