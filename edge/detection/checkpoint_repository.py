"""Repository helpers for detector_checkpoints."""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
from typing import Any

from edge.packet.pcap_naming import format_utc_iso


PHASE4_CHECKPOINT_KEYS = (
    ("mqtt_feature_builder", "mqtt_logs"),
    ("mqtt_feature_rule", "feature_logs"),
    ("mqtt_message_rule", "mqtt_logs"),
    ("mqtt_if", "feature_logs"),
    ("packet_rule", "packet_feature_logs"),
    ("packet_if", "packet_feature_logs"),
    ("trust_score_v2", "detection_events"),
)


def checkpoint_summary_key(detector_name: str, source_table: str) -> str:
    return f"{detector_name}+{source_table}"


def upsert_detector_checkpoint(
    connection: sqlite3.Connection,
    *,
    detector_name: str,
    source_table: str,
    last_processed_id: int | None,
    last_completed_window_end: datetime | None,
    updated_at: datetime,
) -> None:
    if last_processed_id is not None and last_processed_id < 0:
        raise ValueError("last_processed_id must be non-negative")

    connection.execute(
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
        """,
        {
            "detector_name": detector_name,
            "source_table": source_table,
            "last_processed_id": last_processed_id,
            "last_completed_window_end": _format_optional_utc(
                last_completed_window_end,
                "last_completed_window_end",
            ),
            "updated_at": format_utc_iso(_require_aware_utc(updated_at, "updated_at")),
        },
    )


def get_detector_checkpoint(
    connection: sqlite3.Connection,
    *,
    detector_name: str,
    source_table: str,
) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT detector_name, source_table, last_processed_id,
               last_completed_window_end, updated_at
        FROM detector_checkpoints
        WHERE detector_name = ?
          AND source_table = ?
        """,
        (detector_name, source_table),
    ).fetchone()
    return _checkpoint_row_to_dict(row) if row is not None else None


def list_phase4_checkpoint_summary(
    connection: sqlite3.Connection,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for detector_name, source_table in PHASE4_CHECKPOINT_KEYS:
        row = get_detector_checkpoint(
            connection,
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


def _checkpoint_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "detector_name": row["detector_name"],
        "source_table": row["source_table"],
        "last_processed_id": row["last_processed_id"],
        "last_completed_window_end": row["last_completed_window_end"],
        "updated_at": row["updated_at"],
    }


def _format_optional_utc(value: datetime | None, field_name: str) -> str | None:
    if value is None:
        return None
    return format_utc_iso(_require_aware_utc(value, field_name))


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)
