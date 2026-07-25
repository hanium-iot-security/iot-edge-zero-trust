"""MQTT Feature Producer Runtime입니다.

`produce_mqtt_features_until()`은 Feature 저장과 Producer Checkpoint 갱신을 호출자
Transaction 안에서 처리합니다. 이 Runner는 그 Transaction 경계와 실행 주기, 종료
Signal, 운영 로그만 담당합니다.

Orchestrator는 이 Runner가 갱신한 `mqtt_feature_builder + mqtt_logs` Checkpoint를
읽기만 합니다. 따라서 이 서비스가 멈추면 Orchestrator의 `cycle_cutoff`도 전진하지
않습니다.

기존 `edge.features.collect_feature_logs` CLI는 호환 Wrapper로 남지만 Checkpoint를
갱신하지 않습니다. 두 경로를 동시에 실행하면 Feature와 Checkpoint가 어긋나므로,
Cutover 시 기존 Cron을 중지한 뒤 이 서비스를 사용합니다.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
import logging
import signal
from threading import Event
import time

from sqlalchemy.orm import Session

from backend.app.config import Settings, settings
from backend.app.database import SessionLocal
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.phase4_time import floor_window_start, format_db_utc
from edge.features.collect_feature_logs import (
    MQTT_FEATURE_BUILDER,
    MQTT_LOGS_SOURCE,
    ProducerRunResult,
    produce_mqtt_features_until,
)

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]


class UtcFormatter(logging.Formatter):
    """Format log timestamps in UTC regardless of the host timezone."""

    converter = time.gmtime


class GracefulShutdown:
    """Signal-backed shutdown state with an interruptible wait."""

    def __init__(self) -> None:
        self._event = Event()

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    def request(self, signum: int, _frame: object | None) -> None:
        logger.info("Shutdown signal received (signum=%s)", signum)
        self._event.set()

    def install(self) -> None:
        signal.signal(signal.SIGTERM, self.request)
        signal.signal(signal.SIGINT, self.request)

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def compute_producer_cutoff(now: datetime) -> datetime:
    """마지막으로 닫힌 10초 Window의 끝을 반환합니다.

    현재 열린 Window는 아직 메시지가 더 들어올 수 있으므로 처리 대상이 아닙니다.
    현재 시각이 속한 Window의 시작 시각이 곧 "마지막 닫힌 Window의 끝"입니다.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware UTC")
    # datetime.now()는 마이크로초를 포함하지만 Window 경계 계약은 정수 초만 허용한다.
    return floor_window_start(now.astimezone(timezone.utc).replace(microsecond=0))


def produce_once(
    db: Session,
    *,
    now: datetime,
) -> ProducerRunResult | None:
    """닫힌 Window가 새로 생겼을 때만 Producer를 실행합니다.

    Checkpoint가 이미 cutoff까지 도달했으면 아무것도 하지 않고 `None`을 반환합니다.
    같은 cutoff로 다시 실행하는 것 자체는 안전하지만, 불필요한 Write와 로그를 줄입니다.
    """
    cutoff = compute_producer_cutoff(now)
    completed = checkpoints.get_completed_window_end(
        db,
        detector_name=MQTT_FEATURE_BUILDER,
        source_table=MQTT_LOGS_SOURCE,
    )
    if completed is not None and completed >= cutoff:
        return None
    return produce_mqtt_features_until(db, producer_cutoff=cutoff)


def run_producer_cycle(
    *,
    session_factory: SessionFactory = SessionLocal,
    now: datetime,
) -> ProducerRunResult | None:
    """한 Cycle을 단일 Transaction으로 처리합니다.

    Feature 저장과 Checkpoint 갱신이 함께 Commit되거나 함께 Rollback되어야 합니다.
    한쪽만 남으면 Feature가 중복되거나 Source Row가 영구히 건너뛰어집니다.
    """
    db = session_factory()
    try:
        with db.begin():
            result = produce_once(db, now=now)
    finally:
        db.close()

    if result is None:
        return None

    logger.info(
        "event=MQTT_FEATURE_PRODUCED cutoff=%s selected=%d created=%d late_source=%d "
        "last_processed_id=%s->%s completed_window_end=%s->%s",
        format_db_utc(result.cutoff),
        result.selected_count,
        result.created_feature_count,
        result.late_source_count,
        result.last_processed_id_before,
        result.last_processed_id_after,
        format_db_utc(result.completed_window_end_before)
        if result.completed_window_end_before is not None
        else None,
        format_db_utc(result.completed_window_end_after),
    )
    return result


def run_producer_loop(
    *,
    shutdown: GracefulShutdown,
    interval_seconds: float,
    session_factory: SessionFactory = SessionLocal,
    max_cycles: int | None = None,
    clock: Callable[[], datetime] = _now,
) -> int:
    """종료 Signal까지 Cycle을 반복합니다. 실패는 systemd 재시작으로 넘깁니다."""
    if max_cycles is not None and max_cycles <= 0:
        raise ValueError("max_cycles must be positive")
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")

    completed = 0
    while not shutdown.requested:
        run_producer_cycle(session_factory=session_factory, now=clock())

        completed += 1
        if max_cycles is not None and completed >= max_cycles:
            break
        if shutdown.wait(interval_seconds):
            break

    return completed


def load_interval_seconds(app_settings: Settings = settings) -> float:
    return app_settings.mqtt_feature_builder_interval_seconds


def print_checkpoint_status(session_factory: SessionFactory = SessionLocal) -> None:
    """Pi에서 Watermark 전진을 눈으로 확인할 때 사용합니다."""
    with session_factory() as db:
        row = checkpoints.get_detector_checkpoint(
            db,
            detector_name=MQTT_FEATURE_BUILDER,
            source_table=MQTT_LOGS_SOURCE,
        )
    if row is None:
        print(f"{MQTT_FEATURE_BUILDER}+{MQTT_LOGS_SOURCE}: Checkpoint 없음")
        return
    print(
        f"{MQTT_FEATURE_BUILDER}+{MQTT_LOGS_SOURCE}: "
        f"last_processed_id={row['last_processed_id']} "
        f"last_completed_window_end={row['last_completed_window_end']} "
        f"updated_at={row['updated_at']}"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MQTT Feature Producer Runtime")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--loop", action="store_true", help="종료 Signal까지 반복 실행")
    mode.add_argument("--once", action="store_true", help="한 Cycle만 실행")
    mode.add_argument("--status", action="store_true", help="현재 Producer Checkpoint 출력")
    parser.add_argument("--cycles", type=int, default=None, help="--loop에서 실행할 최대 Cycle 수")
    parser.add_argument("--interval", type=float, default=None, help="Cycle 간격(초)")
    return parser.parse_args(argv)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        UtcFormatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging()

    if args.status:
        print_checkpoint_status()
        return 0

    if args.once:
        run_producer_cycle(now=_now())
        return 0

    interval = args.interval if args.interval is not None else load_interval_seconds()
    shutdown = GracefulShutdown()
    shutdown.install()
    completed = run_producer_loop(
        shutdown=shutdown,
        interval_seconds=interval,
        max_cycles=args.cycles,
    )
    logger.info("MQTT feature builder stopped (cycles=%d)", completed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
