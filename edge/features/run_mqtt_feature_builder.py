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
from pathlib import Path
import signal
from threading import Event
import time

from sqlalchemy import text
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
from edge.runtime_lock import RuntimeLockError, resolve_lock_path, single_instance_lock

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

BOOTSTRAP_CONFIRM_TOKEN = "BOOTSTRAP-MQTT-FEATURE-CHECKPOINT"


class ProducerCheckpointMissingError(Exception):
    """Producer Checkpoint가 없어 어디서부터 처리해야 할지 알 수 없습니다."""


class ProducerBootstrapError(Exception):
    """Bootstrap을 안전하게 수행할 수 없는 상태입니다."""


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
    if completed is None:
        # Checkpoint가 없으면 "처음부터 전부"가 되어, 기존 운영 DB의 과거 mqtt_logs가
        # 모두 Phase 4 Feature로 다시 만들어진다. 기존 MVP Feature는 공백 형식
        # Timestamp("2026-07-25 12:00:00"), Phase 4는 ISO 형식("...T12:00:00Z")이라
        # UNIQUE(device_id, window_start, window_end)가 같은 Window를 다른 문자열로
        # 보고 중복 Row를 허용한다. 시작점은 반드시 명시적으로 정해야 한다.
        raise ProducerCheckpointMissingError(
            f"{MQTT_FEATURE_BUILDER}+{MQTT_LOGS_SOURCE} Producer Checkpoint가 없습니다. "
            "신규 DB는 --bootstrap으로 시작 시점을 정하고, 기존 운영 DB는 "
            "edge/scripts/run_phase4_cutover.py로 Checkpoint를 초기화하세요."
        )
    if completed >= cutoff:
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


def producer_lock_path(app_settings: Settings = settings) -> Path:
    """Producer Runtime의 중복 실행을 막는 Lock 경로입니다."""
    if app_settings.mqtt_feature_builder_lock_path.strip():
        return Path(app_settings.mqtt_feature_builder_lock_path.strip())
    return resolve_lock_path(
        app_settings.database_url,
        suffix=".mqtt-feature-builder.lock",
        fallback="data/mqtt-feature-builder.lock",
    )


def bootstrap_producer_checkpoint(
    db: Session,
    *,
    now: datetime,
    allow_existing_source: bool = False,
) -> datetime:
    """신규 DB의 Producer 시작 시점을 명시적으로 기록합니다.

    이미 `mqtt_logs`가 쌓인 DB는 이 경로를 쓰지 않습니다. 그 경우 어디까지 처리된
    것으로 볼지는 Cutover가 동일 Snapshot에서 계산해야 합니다.
    """
    existing = checkpoints.get_detector_checkpoint(
        db,
        detector_name=MQTT_FEATURE_BUILDER,
        source_table=MQTT_LOGS_SOURCE,
    )
    if existing is not None:
        raise ProducerBootstrapError(
            f"{MQTT_FEATURE_BUILDER}+{MQTT_LOGS_SOURCE} Checkpoint가 이미 있습니다: "
            f"last_completed_window_end={existing['last_completed_window_end']}"
        )

    source_count = int(db.execute(text("SELECT COUNT(*) FROM mqtt_logs")).scalar() or 0)
    if source_count and not allow_existing_source:
        raise ProducerBootstrapError(
            f"mqtt_logs에 이미 {source_count}건이 있습니다. 기존 데이터가 있는 DB는 "
            "edge/scripts/run_phase4_cutover.py로 Checkpoint를 초기화하세요. "
            "과거 Window를 의도적으로 건너뛰려면 --allow-existing-source를 사용하세요."
        )

    cutoff = compute_producer_cutoff(now)
    checkpoints.upsert_detector_checkpoint(
        db,
        detector_name=MQTT_FEATURE_BUILDER,
        source_table=MQTT_LOGS_SOURCE,
        last_processed_id=None,
        last_completed_window_end=cutoff,
        updated_at=cutoff,
    )
    return cutoff


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
    mode.add_argument(
        "--bootstrap",
        action="store_true",
        help="신규 DB의 Producer 시작 시점을 기록합니다(기존 운영 DB는 Cutover 사용)",
    )
    parser.add_argument("--cycles", type=int, default=None, help="--loop에서 실행할 최대 Cycle 수")
    parser.add_argument("--interval", type=float, default=None, help="Cycle 간격(초)")
    parser.add_argument(
        "--allow-existing-source",
        action="store_true",
        help="--bootstrap에서 기존 mqtt_logs의 과거 Window를 의도적으로 건너뜁니다",
    )
    parser.add_argument("--confirm", default=None, help=f"--bootstrap 확인 토큰({BOOTSTRAP_CONFIRM_TOKEN})")
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

    if args.bootstrap:
        if args.confirm != BOOTSTRAP_CONFIRM_TOKEN:
            logger.error("--bootstrap에는 --confirm %s 가 필요합니다", BOOTSTRAP_CONFIRM_TOKEN)
            return 2
        db = SessionLocal()
        try:
            with db.begin():
                cutoff = bootstrap_producer_checkpoint(
                    db,
                    now=_now(),
                    allow_existing_source=args.allow_existing_source,
                )
        except ProducerBootstrapError as exc:
            logger.error("Bootstrap 실패: %s", exc)
            return 2
        finally:
            db.close()
        logger.warning(
            "Producer Checkpoint bootstrapped (last_completed_window_end=%s)",
            format_db_utc(cutoff),
        )
        return 0

    # Producer는 상시 서비스 하나만 실행되어야 한다. 두 프로세스가 같은 Checkpoint를
    # 전진시키면 동일 Window를 중복 처리하려 시도한다.
    lock_path = producer_lock_path()
    try:
        with single_instance_lock(lock_path):
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
    except RuntimeLockError as exc:
        logger.error("이미 다른 Producer 인스턴스가 실행 중입니다: %s", exc)
        return 3
    except ProducerCheckpointMissingError as exc:
        logger.error("%s", exc)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
