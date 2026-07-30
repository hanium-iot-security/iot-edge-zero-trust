"""Shared Phase 4 detector runtime contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy.orm import Session

from edge.detection.phase4_time import require_utc_window_boundary


@dataclass(frozen=True)
class DetectorRunResult:
    detector_name: str
    source_table: str
    range_start: datetime
    cutoff: datetime
    selected_count: int
    created_event_count: int
    last_processed_id_before: int | None
    last_processed_id_after: int | None
    completed_window_end_before: datetime | None
    completed_window_end_after: datetime
    capture_session_id: str | None = None


class DetectorStage(Protocol):
    detector_name: str
    source_table: str

    def run_until(
        self,
        db: Session,
        *,
        cycle_range_start: datetime,
        cycle_cutoff: datetime,
    ) -> DetectorRunResult:
        ...


def validate_cycle_window(
    *,
    cycle_range_start: datetime,
    cycle_cutoff: datetime,
) -> tuple[datetime, datetime]:
    range_start = require_utc_window_boundary(cycle_range_start, "cycle_range_start")
    cutoff = require_utc_window_boundary(cycle_cutoff, "cycle_cutoff")
    if range_start > cutoff:
        raise ValueError("cycle_range_start must be earlier than or equal to cycle_cutoff")
    return range_start, cutoff
