"""Processing boundaries and dataset exclusion for audited maintenance windows."""

from datetime import datetime, timezone

from edge.detection.phase4_time import parse_db_utc
from edge.maintenance.planned import approved_intervals, get_processing_cutoff


def cap_processing_cutoff(db, cutoff: datetime) -> datetime:
    boundary = get_processing_cutoff(db)
    return min(cutoff, boundary) if boundary is not None else cutoff


def require_processing_cutoff(db, cutoff: datetime) -> None:
    if cap_processing_cutoff(db, cutoff) < cutoff:
        raise RuntimeError("planned maintenance holds processing at the closed capture boundary")


def maintenance_windows(db) -> tuple[tuple[datetime, datetime], ...]:
    return tuple(
        (parse_db_utc(row["window_start"], "maintenance_start"),
         parse_db_utc(row["window_end"], "maintenance_end"))
        for row in approved_intervals(db)
    )


def overlaps_maintenance(windows, start: datetime, end: datetime) -> bool:
    """Half-open overlap: the final pre-stop window and first full new window stay eligible."""
    return any(start < right and left < end for left, right in windows)


def dataset_maintenance_windows(db) -> tuple[tuple[datetime, datetime], ...]:
    windows = maintenance_windows(db)
    boundary = get_processing_cutoff(db)
    if boundary is not None:
        windows += ((boundary, datetime.max.replace(tzinfo=timezone.utc)),)
    return windows
