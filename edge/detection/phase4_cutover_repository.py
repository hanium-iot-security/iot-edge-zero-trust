"""Phase 4 cutover checkpoint initialization."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from db.migration_runner import connect_database
from edge.detection import checkpoint_repository as checkpoints
from edge.packet.pcap_naming import format_utc_iso


LEGACY_MIGRATION_REASON = "LEGACY_MIGRATION"


def initialize_phase4_cutover(
    database_path: Path,
    phase4_cutover_at: datetime,
) -> Mapping[str, object]:
    db_path = Path(database_path)
    if not db_path.exists():
        raise FileNotFoundError(f"database_path does not exist: {db_path}")
    if not db_path.is_file():
        raise ValueError(f"database_path must be a SQLite file: {db_path}")

    cutover_at = _require_utc(phase4_cutover_at, "phase4_cutover_at")

    connection = connect_database(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE;")
        checkpoint_values = _calculate_cutover_checkpoints(connection, cutover_at)
        legacy_migration_event_count = _mark_legacy_detection_events(
            connection,
            cutover_at,
        )

        for detector_name, source_table in checkpoints.PHASE4_CHECKPOINT_KEYS:
            value = checkpoint_values[(detector_name, source_table)]
            checkpoints.upsert_detector_checkpoint(
                connection,
                detector_name=detector_name,
                source_table=source_table,
                last_processed_id=value["last_processed_id"],
                last_completed_window_end=value["last_completed_window_end"],
                updated_at=cutover_at,
            )

        expected_summary = _checkpoint_values_to_summary(checkpoint_values)
        stored_summary = checkpoints.list_phase4_checkpoint_summary(connection)
        if stored_summary != expected_summary:
            raise RuntimeError("stored checkpoint rows do not match cutover summary")

        summary: dict[str, object] = {
            "legacy_migration_event_count": legacy_migration_event_count,
            "checkpoints": stored_summary,
        }
        connection.execute("COMMIT;")
        return summary
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK;")
        raise
    finally:
        connection.close()


def _calculate_cutover_checkpoints(
    connection: sqlite3.Connection,
    cutover_at: datetime,
) -> dict[tuple[str, str], dict[str, Any]]:
    mqtt_ready_through = _existing_completed_window_end(
        connection,
        detector_name="mqtt_feature_builder",
        source_table="mqtt_logs",
    )
    packet_processed_id, packet_ready_through = _packet_feature_checkpoint(connection)
    trust_processed_id = _max_detection_event_id_before_cutover(connection, cutover_at)

    values = _empty_checkpoint_values()
    values[("mqtt_feature_builder", "mqtt_logs")] = {
        "last_processed_id": _max_mqtt_log_id_before(connection, mqtt_ready_through),
        "last_completed_window_end": mqtt_ready_through,
    }
    values[("mqtt_feature_rule", "feature_logs")] = {
        "last_processed_id": _max_feature_log_id_through(connection, mqtt_ready_through),
        "last_completed_window_end": mqtt_ready_through,
    }
    values[("mqtt_message_rule", "mqtt_logs")] = {
        "last_processed_id": _max_mqtt_log_id_before(connection, mqtt_ready_through),
        "last_completed_window_end": mqtt_ready_through,
    }
    values[("mqtt_if", "feature_logs")] = {
        "last_processed_id": _max_feature_log_id_through(connection, mqtt_ready_through),
        "last_completed_window_end": mqtt_ready_through,
    }
    values[("packet_rule", "packet_feature_logs")] = {
        "last_processed_id": packet_processed_id,
        "last_completed_window_end": packet_ready_through,
    }
    values[("packet_if", "packet_feature_logs")] = {
        "last_processed_id": packet_processed_id,
        "last_completed_window_end": packet_ready_through,
    }
    values[("trust_score_v2", "detection_events")] = {
        "last_processed_id": trust_processed_id,
        "last_completed_window_end": cutover_at if trust_processed_id is not None else None,
    }
    return values


def _empty_checkpoint_values() -> dict[tuple[str, str], dict[str, Any]]:
    return {
        key: {"last_processed_id": None, "last_completed_window_end": None}
        for key in checkpoints.PHASE4_CHECKPOINT_KEYS
    }


def _existing_completed_window_end(
    connection: sqlite3.Connection,
    *,
    detector_name: str,
    source_table: str,
) -> datetime | None:
    row = checkpoints.get_detector_checkpoint(
        connection,
        detector_name=detector_name,
        source_table=source_table,
    )
    if row is None or row["last_completed_window_end"] is None:
        return None
    return _parse_db_utc(row["last_completed_window_end"])


def _max_mqtt_log_id_before(
    connection: sqlite3.Connection,
    completed_window_end: datetime | None,
) -> int | None:
    if completed_window_end is None:
        return None
    row = connection.execute(
        """
        SELECT MAX(id) AS max_id
        FROM mqtt_logs
        WHERE unixepoch(received_at) < unixepoch(:completed_window_end)
        """,
        {"completed_window_end": format_utc_iso(completed_window_end)},
    ).fetchone()
    return int(row["max_id"]) if row["max_id"] is not None else None


def _max_feature_log_id_through(
    connection: sqlite3.Connection,
    completed_window_end: datetime | None,
) -> int | None:
    if completed_window_end is None:
        return None
    row = connection.execute(
        """
        SELECT MAX(id) AS max_id
        FROM feature_logs
        WHERE unixepoch(window_end) <= unixepoch(:completed_window_end)
        """,
        {"completed_window_end": format_utc_iso(completed_window_end)},
    ).fetchone()
    return int(row["max_id"]) if row["max_id"] is not None else None


def _packet_feature_checkpoint(
    connection: sqlite3.Connection,
) -> tuple[int | None, datetime | None]:
    completed_segment_ids: list[int] = []
    latest_ready_through: datetime | None = None

    sessions = connection.execute(
        """
        SELECT id, first_window_start
        FROM packet_capture_sessions
        WHERE first_window_start IS NOT NULL
        ORDER BY id ASC
        """
    ).fetchall()
    for session in sessions:
        session_ready_through = _completed_prefix_for_session(
            connection,
            capture_session_id=int(session["id"]),
            first_window_start=_parse_db_utc(session["first_window_start"]),
            completed_segment_ids=completed_segment_ids,
        )
        if session_ready_through is not None and (
            latest_ready_through is None or session_ready_through > latest_ready_through
        ):
            latest_ready_through = session_ready_through

    last_processed_id = _max_packet_feature_id_for_segments(
        connection,
        completed_segment_ids,
    )
    return last_processed_id, latest_ready_through


def _completed_prefix_for_session(
    connection: sqlite3.Connection,
    *,
    capture_session_id: int,
    first_window_start: datetime,
    completed_segment_ids: list[int],
) -> datetime | None:
    expected_window_start = first_window_start
    ready_through: datetime | None = None
    rows = connection.execute(
        """
        SELECT id, window_start, window_end, status
        FROM packet_capture_segments
        WHERE capture_session_id = ?
        ORDER BY window_start ASC, id ASC
        """,
        (capture_session_id,),
    ).fetchall()
    for row in rows:
        window_start = _parse_db_utc(row["window_start"])
        if window_start < expected_window_start:
            continue
        if window_start > expected_window_start:
            break
        if row["status"] not in {"PROCESSED", "EMPTY"}:
            break

        window_end = _parse_db_utc(row["window_end"])
        if window_end != window_start + timedelta(seconds=10):
            break

        completed_segment_ids.append(int(row["id"]))
        ready_through = window_end
        expected_window_start = window_end

    return ready_through


def _max_packet_feature_id_for_segments(
    connection: sqlite3.Connection,
    segment_ids: list[int],
) -> int | None:
    if not segment_ids:
        return None
    placeholders = ",".join("?" for _ in segment_ids)
    row = connection.execute(
        f"""
        SELECT MAX(id) AS max_id
        FROM packet_feature_logs
        WHERE capture_segment_id IN ({placeholders})
        """,
        tuple(segment_ids),
    ).fetchone()
    return int(row["max_id"]) if row["max_id"] is not None else None


def _max_detection_event_id_before_cutover(
    connection: sqlite3.Connection,
    cutover_at: datetime,
) -> int | None:
    row = connection.execute(
        """
        SELECT MAX(id) AS max_id
        FROM detection_events
        WHERE detected_at IS NULL
           OR unixepoch(detected_at) < unixepoch(:cutover_at)
        """,
        {"cutover_at": format_utc_iso(cutover_at)},
    ).fetchone()
    return int(row["max_id"]) if row["max_id"] is not None else None


def _mark_legacy_detection_events(
    connection: sqlite3.Connection,
    cutover_at: datetime,
) -> int:
    result = connection.execute(
        """
        UPDATE detection_events
        SET processed_at = :processed_at,
            processing_reason = :processing_reason
        WHERE processed_at IS NULL
          AND (
              detected_at IS NULL
              OR unixepoch(detected_at) < unixepoch(:processed_at)
          )
        """,
        {
            "processed_at": format_utc_iso(cutover_at),
            "processing_reason": LEGACY_MIGRATION_REASON,
        },
    )
    return int(result.rowcount or 0)


def _checkpoint_values_to_summary(
    values: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        checkpoints.checkpoint_summary_key(detector_name, source_table): {
            "last_processed_id": value["last_processed_id"],
            "last_completed_window_end": _format_optional_utc_string(
                value["last_completed_window_end"]
            ),
        }
        for detector_name, source_table in checkpoints.PHASE4_CHECKPOINT_KEYS
        for value in [values[(detector_name, source_table)]]
    }


def _format_optional_utc_string(value: datetime | None) -> str | None:
    return format_utc_iso(value) if value is not None else None


def _parse_db_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        else:
            text = text.replace(" ", "T")
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _require_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC offset")
    return value.astimezone(timezone.utc).replace(microsecond=0)
