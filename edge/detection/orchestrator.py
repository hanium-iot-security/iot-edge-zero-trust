"""Phase 4 detection orchestrator core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable

from sqlalchemy.orm import Session

from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.detector_contract import (
    DetectorRunResult,
    DetectorStage,
    validate_cycle_window,
)
from edge.detection.phase4_time import parse_db_utc


SessionFactory = Callable[[], Session]


@dataclass(frozen=True)
class OrchestratorRunResult:
    range_start: datetime
    cutoff: datetime
    stage_results: list[DetectorRunResult]


def run_detection_cycle(
    *,
    session_factory: SessionFactory,
    stages: Iterable[DetectorStage],
    cycle_range_start: datetime,
    cycle_cutoff: datetime,
) -> OrchestratorRunResult:
    range_start, cutoff = validate_cycle_window(
        cycle_range_start=cycle_range_start,
        cycle_cutoff=cycle_cutoff,
    )
    results: list[DetectorRunResult] = []

    for stage in stages:
        db = session_factory()
        try:
            with db.begin():
                result = stage.run_until(
                    db,
                    cycle_range_start=range_start,
                    cycle_cutoff=cutoff,
                )
            results.append(result)
        finally:
            db.close()

    return OrchestratorRunResult(
        range_start=range_start,
        cutoff=cutoff,
        stage_results=results,
    )


def ensure_checkpoint_completed(
    db: Session,
    *,
    detector_name: str,
    source_table: str,
    cutoff: datetime,
) -> None:
    completed_window_end = checkpoints.get_completed_window_end(
        db,
        detector_name=detector_name,
        source_table=source_table,
    )
    if completed_window_end is None:
        raise RuntimeError(f"required checkpoint missing: {detector_name}+{source_table}")
    if completed_window_end < cutoff:
        raise RuntimeError(f"required checkpoint has not reached cutoff: {detector_name}+{source_table}")


def checkpoint_ready_for_cutoff(row: dict, cutoff: datetime) -> bool:
    value = row.get("last_completed_window_end")
    if value is None:
        return False
    return parse_db_utc(value, "last_completed_window_end") >= cutoff
