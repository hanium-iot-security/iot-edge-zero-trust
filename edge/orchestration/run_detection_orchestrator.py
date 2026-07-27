"""Detection Orchestrator 실행 Runtime입니다.

Cycle 순서(세부계획 2.4):

    단일 인스턴스 Lock
    → 활성 Feature Producer Watermark 조회
    → cycle_range_start·cycle_cutoff 확정
    → 활성 Required Detector Snapshot
    → Stage 실행 (Stage별 독립 Transaction)
    → Required Detector 완료 Barrier 확인
    → Trust Score v2 실행
    → Trust Checkpoint 완료 확인
    → Cycle 완료 로그

한 Cycle의 모든 Stage는 **같은** `cycle_range_start`·`cycle_cutoff`를 받습니다. Stage마다
현재 시각을 다시 계산하면 서로 다른 Window의 Event가 한 Trust 계산에 섞입니다.

현재 Packet 계층(Packet Rule·Packet IF)은 `develop`에 없어 MQTT 단독 Cycle로 동작합니다.
세부계획 2.4의 "Packet 계층이 비활성화됐거나 required=false이면 Packet Watermark를
Barrier에서 제외하고 MQTT 단독 Trust Cycle을 정상 수행한다"에 해당합니다. Packet Session
Gap Drain은 Packet Stage와 Core의 Ready Range가 들어온 뒤 연결합니다.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
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
from edge.detection.checkpoint_repository import (
    PHASE4_CHECKPOINT_KEYS,
    checkpoint_summary_key,
)
from edge.detection.detector_contract import DetectorRunResult
from edge.detection.orchestrator import ensure_checkpoint_completed, run_detection_cycle
from edge.detection.phase4_time import floor_window_start, format_db_utc, parse_db_utc
from edge.features.collect_feature_logs import MQTT_FEATURE_BUILDER, MQTT_LOGS_SOURCE
from edge.orchestration.stage_registry import StageRegistry, load_stage_registry
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.runtime_lock import resolve_lock_path as _resolve_lock_path
from edge.trust.trust_score_v2 import (
    TRUST_DETECTOR_NAME,
    TRUST_SOURCE_TABLE,
    TrustScoreV2RunResult,
    apply_trust_score_v2_until,
)

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

CYCLE_COMPLETED = "COMPLETED"
CYCLE_SKIPPED_NO_WATERMARK = "SKIPPED_NO_WATERMARK"
CYCLE_SKIPPED_NO_NEW_WINDOW = "SKIPPED_NO_NEW_WINDOW"


@dataclass(frozen=True)
class CycleOutcome:
    status: str
    range_start: datetime | None = None
    cutoff: datetime | None = None
    stage_results: list[DetectorRunResult] = field(default_factory=list)
    trust_result: TrustScoreV2RunResult | None = None


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


def resolve_lock_path(app_settings: Settings = settings) -> Path:
    """설정된 Lock 경로 또는 DB 파일 옆의 기본 경로를 반환합니다."""
    if app_settings.orchestrator_lock_path.strip():
        return Path(app_settings.orchestrator_lock_path.strip())
    return _resolve_lock_path(
        app_settings.database_url,
        suffix=".orchestrator.lock",
        fallback="data/detection-orchestrator.lock",
    )


def resolve_cycle_cutoff(db: Session) -> datetime | None:
    """활성 Feature Producer Watermark로 cutoff를 확정합니다.

    MQTT Feature Producer가 갱신한 Checkpoint만 읽습니다. Orchestrator는 Producer
    Checkpoint를 직접 전진시키지 않습니다.
    """
    return checkpoints.get_completed_window_end(
        db,
        detector_name=MQTT_FEATURE_BUILDER,
        source_table=MQTT_LOGS_SOURCE,
    )


def resolve_cycle_range_start(
    db: Session,
    *,
    registry: StageRegistry,
    cutoff: datetime,
) -> datetime:
    """이번 Cycle이 다룰 Window 하한을 정합니다.

    Stage는 자신의 Checkpoint 이후 Row만 처리하므로 range_start는 하한일 뿐입니다.
    다만 너무 늦게 잡으면 아직 처리되지 않은 과거 Window를 건너뛰게 되므로, 활성
    Stage와 Trust의 완료 Window 중 가장 이른 값을 사용합니다. 아무 Stage도 진행하지
    않은 최초 실행에서는 가장 오래된 Source Window부터 시작합니다.
    """
    completed: list[datetime | None] = []
    for configured in registry.required_stages:
        completed.append(
            checkpoints.get_completed_window_end(
                db,
                detector_name=configured.stage.detector_name,
                source_table=configured.stage.source_table,
            )
        )
    completed.append(
        checkpoints.get_completed_window_end(
            db,
            detector_name=TRUST_DETECTOR_NAME,
            source_table=TRUST_SOURCE_TABLE,
        )
    )

    known = [value for value in completed if value is not None]
    if known and len(known) == len(completed):
        return min(min(known), cutoff)

    earliest_source = earliest_source_window_start(db)
    if earliest_source is None:
        return min(known) if known else cutoff
    if known:
        return min(min(known), earliest_source, cutoff)
    return min(earliest_source, cutoff)


def earliest_source_window_start(db: Session) -> datetime | None:
    """아직 처리되지 않은 가장 오래된 Source Window의 시작 시각입니다."""
    candidates: list[datetime] = []

    feature_window = db.execute(text("SELECT MIN(window_start) FROM feature_logs")).scalar()
    if feature_window is not None:
        candidates.append(floor_window_start(parse_db_utc(feature_window, "window_start")))

    mqtt_received = db.execute(text("SELECT MIN(received_at) FROM mqtt_logs")).scalar()
    if mqtt_received is not None:
        candidates.append(floor_window_start(parse_db_utc(mqtt_received, "received_at")))

    return min(candidates) if candidates else None


def run_orchestration_cycle(
    *,
    session_factory: SessionFactory = SessionLocal,
    registry: StageRegistry,
) -> CycleOutcome:
    """한 Cycle을 실행합니다.

    Stage는 각각 독립 Transaction으로 실행되므로 성공한 Stage의 Event·Checkpoint는
    다른 Stage 실패와 무관하게 유지됩니다. Required Stage가 모두 cutoff까지 완료된
    뒤에만 Trust를 호출합니다.
    """
    with session_factory() as db:
        cutoff = resolve_cycle_cutoff(db)
        if cutoff is None:
            logger.info(
                "event=CYCLE_SKIPPED reason=NO_PRODUCER_WATERMARK "
                "producer=%s+%s",
                MQTT_FEATURE_BUILDER,
                MQTT_LOGS_SOURCE,
            )
            return CycleOutcome(status=CYCLE_SKIPPED_NO_WATERMARK)
        range_start = resolve_cycle_range_start(db, registry=registry, cutoff=cutoff)

    if range_start >= cutoff:
        logger.debug(
            "event=CYCLE_SKIPPED reason=NO_NEW_WINDOW range_start=%s cutoff=%s",
            format_db_utc(range_start),
            format_db_utc(cutoff),
        )
        return CycleOutcome(
            status=CYCLE_SKIPPED_NO_NEW_WINDOW,
            range_start=range_start,
            cutoff=cutoff,
        )

    logger.info(
        "event=CYCLE_STARTED range_start=%s cutoff=%s enabled=%s required=%s",
        format_db_utc(range_start),
        format_db_utc(cutoff),
        ",".join(registry.enabled_names),
        ",".join(registry.required_names),
    )

    stage_results: list[DetectorRunResult] = []
    for configured in registry.stages:
        try:
            detection = run_detection_cycle(
                session_factory=session_factory,
                stages=(configured.stage,),
                cycle_range_start=range_start,
                cycle_cutoff=cutoff,
            )
        except Exception:
            logger.exception(
                "event=STAGE_FAILED detector_name=%s source_table=%s required=%s "
                "cycle_range_start=%s cycle_cutoff=%s",
                configured.stage.detector_name,
                configured.stage.source_table,
                configured.required,
                format_db_utc(range_start),
                format_db_utc(cutoff),
            )
            if configured.required:
                raise
            continue

        stage_results.extend(detection.stage_results)
        for stage_result in detection.stage_results:
            logger.info(
                "event=STAGE_DONE detector=%s source=%s selected=%d created_events=%d "
                "completed_window_end=%s",
                stage_result.detector_name,
                stage_result.source_table,
                stage_result.selected_count,
                stage_result.created_event_count,
                format_db_utc(stage_result.completed_window_end_after),
            )

    with session_factory() as db:
        for configured in registry.required_stages:
            ensure_checkpoint_completed(
                db,
                detector_name=configured.stage.detector_name,
                source_table=configured.stage.source_table,
                cutoff=cutoff,
            )

    db = session_factory()
    try:
        with db.begin():
            trust_result = apply_trust_score_v2_until(
                db,
                cycle_range_start=range_start,
                cycle_cutoff=cutoff,
            )
    finally:
        db.close()

    with session_factory() as db:
        ensure_checkpoint_completed(
            db,
            detector_name=TRUST_DETECTOR_NAME,
            source_table=TRUST_SOURCE_TABLE,
            cutoff=cutoff,
        )

    logger.info(
        "event=CYCLE_COMPLETED range_start=%s cutoff=%s stages=%d trust_events=%d "
        "trust_history=%d isolations=%d firewall_pending=%d",
        format_db_utc(range_start),
        format_db_utc(cutoff),
        len(stage_results),
        trust_result.processed_event_count,
        trust_result.created_history_count,
        trust_result.created_isolation_count,
        trust_result.created_firewall_rule_count,
    )
    return CycleOutcome(
        status=CYCLE_COMPLETED,
        range_start=range_start,
        cutoff=cutoff,
        stage_results=stage_results,
        trust_result=trust_result,
    )


def run_orchestrator_loop(
    *,
    registry: StageRegistry,
    shutdown: GracefulShutdown,
    interval_seconds: float,
    session_factory: SessionFactory = SessionLocal,
    max_cycles: int | None = None,
) -> int:
    if max_cycles is not None and max_cycles <= 0:
        raise ValueError("max_cycles must be positive")
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")

    completed = 0
    while not shutdown.requested:
        run_orchestration_cycle(session_factory=session_factory, registry=registry)

        completed += 1
        if max_cycles is not None and completed >= max_cycles:
            break
        if shutdown.wait(interval_seconds):
            break

    return completed


def print_checkpoint_status(session_factory: SessionFactory = SessionLocal) -> None:
    """Phase 4 Checkpoint 7개의 현재 상태를 출력합니다."""
    with session_factory() as db:
        rows = [
            (
                checkpoint_summary_key(detector_name, source_table),
                checkpoints.get_detector_checkpoint(
                    db,
                    detector_name=detector_name,
                    source_table=source_table,
                ),
            )
            for detector_name, source_table in PHASE4_CHECKPOINT_KEYS
        ]
    for key, row in rows:
        status = "PRESENT" if row is not None else "MISSING"
        row = row or {}
        print(
            f"{key}: status={status} "
            f"last_processed_id={row.get('last_processed_id')} "
            f"last_completed_window_end={row.get('last_completed_window_end')} "
            f"updated_at={row.get('updated_at')}"
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 4 Detection Orchestrator")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--loop", action="store_true", help="종료 Signal까지 반복 실행")
    mode.add_argument("--once", action="store_true", help="한 Cycle만 실행")
    mode.add_argument("--status", action="store_true", help="Phase 4 Checkpoint 상태 출력")
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

    registry = load_stage_registry()
    logger.info(
        "Orchestrator stages enabled=%s required=%s packet_layer_enabled=%s",
        ",".join(registry.enabled_names),
        ",".join(registry.required_names),
        registry.packet_layer_enabled,
    )

    try:
        with single_instance_lock(resolve_lock_path()):
            if args.once:
                run_orchestration_cycle(registry=registry)
                return 0

            interval = (
                args.interval
                if args.interval is not None
                else settings.orchestrator_interval_seconds
            )
            shutdown = GracefulShutdown()
            shutdown.install()
            completed = run_orchestrator_loop(
                registry=registry,
                shutdown=shutdown,
                interval_seconds=interval,
                max_cycles=args.cycles,
            )
            logger.info("Detection orchestrator stopped (cycles=%d)", completed)
            return 0
    except RuntimeLockError as exc:
        logger.error("이미 다른 Orchestrator 인스턴스가 실행 중입니다: %s", exc)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
