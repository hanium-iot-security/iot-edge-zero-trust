"""SQLAlchemy runtime repository for detector_checkpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from edge.detection.checkpoint_repository import (
    PHASE4_CHECKPOINT_KEYS,
    checkpoint_summary_key,
)
from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_whole_second


VALID_CHECKPOINT_KEYS = set(PHASE4_CHECKPOINT_KEYS)


def validate_checkpoint_key(detector_name: str, source_table: str) -> None:
    if (detector_name, source_table) not in VALID_CHECKPOINT_KEYS:
        raise ValueError(
            f"unknown Phase 4 checkpoint key: {detector_name}+{source_table}"
        )


def get_detector_checkpoint(
    db: Session,
    *,
    detector_name: str,
    source_table: str,
) -> dict[str, Any] | None:
    validate_checkpoint_key(detector_name, source_table)
    row = db.execute(
        text(
            """
            SELECT detector_name, source_table, last_processed_id,
                   last_completed_window_end, updated_at
            FROM detector_checkpoints
            WHERE detector_name = :detector_name
              AND source_table = :source_table
            """
        ),
        {"detector_name": detector_name, "source_table": source_table},
    ).mappings().one_or_none()
    return dict(row) if row is not None else None


def get_completed_window_end(
    db: Session,
    *,
    detector_name: str,
    source_table: str,
) -> datetime | None:
    row = get_detector_checkpoint(
        db,
        detector_name=detector_name,
        source_table=source_table,
    )
    if row is None or row["last_completed_window_end"] is None:
        return None
    return parse_db_utc(row["last_completed_window_end"], "last_completed_window_end")


def upsert_detector_checkpoint(
    db: Session,
    *,
    detector_name: str,
    source_table: str,
    last_processed_id: int | None,
    last_completed_window_end: datetime | None,
    updated_at: datetime,
) -> None:
    validate_checkpoint_key(detector_name, source_table)
    if last_processed_id is not None and last_processed_id < 0:
        raise ValueError("last_processed_id must be non-negative")
    existing = get_detector_checkpoint(
        db,
        detector_name=detector_name,
        source_table=source_table,
    )
    _validate_checkpoint_progress(
        existing,
        last_processed_id=last_processed_id,
        last_completed_window_end=last_completed_window_end,
    )

    db.execute(
        text(
            """
            INSERT INTO detector_checkpoints (
                detector_name,
                source_table,
                last_processed_id,
                last_completed_window_end,
                updated_at
            )
            VALUES (
                :detector_name,
                :source_table,
                :last_processed_id,
                :last_completed_window_end,
                :updated_at
            )
            ON CONFLICT(detector_name, source_table) DO UPDATE SET
                last_processed_id = excluded.last_processed_id,
                last_completed_window_end = excluded.last_completed_window_end,
                updated_at = excluded.updated_at
            """
        ),
        {
            "detector_name": detector_name,
            "source_table": source_table,
            "last_processed_id": last_processed_id,
            "last_completed_window_end": (
                format_db_utc(last_completed_window_end)
                if last_completed_window_end is not None
                else None
            ),
            "updated_at": format_db_utc(
                require_utc_whole_second(updated_at, "updated_at")
            ),
        },
    )


def _validate_checkpoint_progress(
    existing: dict[str, Any] | None,
    *,
    last_processed_id: int | None,
    last_completed_window_end: datetime | None,
) -> None:
    if existing is None:
        return

    existing_window_end = (
        parse_db_utc(
            existing["last_completed_window_end"],
            "last_completed_window_end",
        )
        if existing["last_completed_window_end"] is not None
        else None
    )
    if existing_window_end is not None:
        if last_completed_window_end is None:
            raise ValueError("detector checkpoint cannot move backwards")
        if last_completed_window_end < existing_window_end:
            raise ValueError("detector checkpoint cannot move backwards")

    existing_id = existing["last_processed_id"]
    if existing_id is not None and (
        last_processed_id is None or last_processed_id < int(existing_id)
    ):
        raise ValueError("detector checkpoint last_processed_id cannot move backwards")


def list_phase4_checkpoint_summary(db: Session) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for detector_name, source_table in PHASE4_CHECKPOINT_KEYS:
        row = get_detector_checkpoint(
            db,
            detector_name=detector_name,
            source_table=source_table,
        )
        if row is None:
            continue
        result[checkpoint_summary_key(detector_name, source_table)] = {
            "last_processed_id": row["last_processed_id"],
            "last_completed_window_end": row["last_completed_window_end"],
        }
    return result
