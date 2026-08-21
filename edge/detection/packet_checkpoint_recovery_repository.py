"""Fixed SQLite reads for packet checkpoint gap recovery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import sqlite3
from typing import Mapping, Sequence

from edge.detection.phase4_time import parse_db_utc


SUPPORTED_DETECTORS = {
    "packet_rule": "packet_feature_logs",
    "packet_if": "packet_feature_logs",
}

PROTECTED_TABLES = (
    "detection_events",
    "trust_score_history",
    "devices",
    "isolation_history",
    "firewall_rules",
    "mqtt_logs",
    "feature_logs",
    "packet_capture_sessions",
    "packet_capture_segments",
    "packet_feature_logs",
)


@dataclass(frozen=True)
class RecoverySessionReadiness:
    session_id: str
    first_window_start: datetime | None
    packet_feature_ready_through: datetime | None
    segment_count: int
    feature_row_count: int
    full_ready: bool
    blocking_reasons: tuple[str, ...]
    live_resume_blocking_reasons: tuple[str, ...] = ()


def get_checkpoint(
    connection: sqlite3.Connection,
    detector_name: str,
    source_table: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT detector_name, source_table, last_processed_id,
               last_completed_window_end, updated_at
        FROM detector_checkpoints
        WHERE detector_name = ? AND source_table = ?
        """,
        (detector_name, source_table),
    ).fetchone()


def snapshot_protected_rows(
    connection: sqlite3.Connection,
    *,
    requested_checkpoint_key: tuple[str, str],
) -> dict[str, tuple[tuple[object, ...], ...]]:
    snapshot = {
        table: tuple(connection.execute(f"SELECT * FROM {table} ORDER BY rowid"))
        for table in PROTECTED_TABLES
    }
    snapshot["detector_checkpoints"] = tuple(
        connection.execute(
            """
            SELECT * FROM detector_checkpoints
            WHERE NOT (detector_name = ? AND source_table = ?)
            ORDER BY detector_name, source_table
            """,
            requested_checkpoint_key,
        )
    )
    return snapshot


def get_capture_session(
    connection: sqlite3.Connection,
    session_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT id, session_id, capture_interface, started_at,
               first_window_start, ended_at, capture_gap_start,
               capture_gap_end, status, created_at, updated_at
        FROM packet_capture_sessions
        WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()


def list_capture_segments(
    connection: sqlite3.Connection,
    session_id: str,
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT pcsg.id, pcsg.capture_session_id, pcsg.file_name,
               pcsg.capture_interface, pcsg.window_start, pcsg.window_end,
               pcsg.status, pcsg.packet_count, pcsg.processed_at,
               pcsg.error_code, pcsg.error_message,
               pcsg.created_at, pcsg.updated_at
        FROM packet_capture_segments pcsg
        JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
        WHERE pcs.session_id = ?
        ORDER BY pcsg.window_start ASC, pcsg.id ASC
        """,
        (session_id,),
    ).fetchall()


def list_running_capture_sessions(
    connection: sqlite3.Connection,
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT session_id, started_at
        FROM packet_capture_sessions
        WHERE status = 'RUNNING'
        ORDER BY started_at ASC, session_id ASC
        """
    ).fetchall()


def list_sessions_between(
    connection: sqlite3.Connection,
    *,
    after_window_end: str,
    before_window_start: str,
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT id, session_id, capture_interface, started_at,
               first_window_start, ended_at, status
        FROM packet_capture_sessions
        WHERE first_window_start IS NOT NULL
          AND unixepoch(first_window_start) > unixepoch(?)
          AND unixepoch(first_window_start) < unixepoch(?)
        ORDER BY first_window_start ASC, id ASC
        """,
        (after_window_end, before_window_start),
    ).fetchall()


def get_existing_recovery(
    connection: sqlite3.Connection,
    *,
    detector_name: str,
    source_table: str,
    target_session_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT id, operation_id, detector_name, source_table,
               current_capture_session_id, target_capture_session_id,
               plan_sha256, created_at
        FROM packet_checkpoint_recoveries
        WHERE detector_name = ?
          AND source_table = ?
          AND target_capture_session_id = ?
        """,
        (detector_name, source_table, target_session_id),
    ).fetchone()


def update_checkpoint_conditionally(
    connection: sqlite3.Connection,
    *,
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> int:
    cursor = connection.execute(
        """
        UPDATE detector_checkpoints
        SET last_completed_window_end = ?, updated_at = ?
        WHERE detector_name = ?
          AND source_table = ?
          AND last_processed_id IS ?
          AND last_completed_window_end = ?
          AND updated_at = ?
        """,
        (
            after["last_completed_window_end"],
            after["updated_at"],
            before["detector_name"],
            before["source_table"],
            before["last_processed_id"],
            before["last_completed_window_end"],
            before["updated_at"],
        ),
    )
    return cursor.rowcount


def insert_recovery_audit(
    connection: sqlite3.Connection,
    *,
    audit: Mapping[str, object],
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO packet_checkpoint_recoveries (
            operation_id, detector_name, source_table,
            current_capture_session_id, target_capture_session_id,
            last_processed_id_before, last_processed_id_after,
            last_completed_window_end_before, last_completed_window_end_after,
            updated_at_before, updated_at_after, plan_sha256, plan_json,
            skipped_session_count, skipped_processable_session_count,
            approved_by, reason, repository_commit, database_path,
            backup_path, backup_sha256
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            audit["operation_id"],
            audit["detector_name"],
            audit["source_table"],
            audit["current_capture_session_id"],
            audit["target_capture_session_id"],
            audit["last_processed_id_before"],
            audit["last_processed_id_after"],
            audit["last_completed_window_end_before"],
            audit["last_completed_window_end_after"],
            audit["updated_at_before"],
            audit["updated_at_after"],
            audit["plan_sha256"],
            audit["plan_json"],
            audit["skipped_session_count"],
            audit["skipped_processable_session_count"],
            audit["approved_by"],
            audit["reason"],
            audit["repository_commit"],
            audit["database_path"],
            audit["backup_path"],
            audit["backup_sha256"],
        ),
    )
    return cursor.rowcount


def get_recovery_audit(
    connection: sqlite3.Connection,
    operation_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT id, operation_id, detector_name, source_table,
               current_capture_session_id, target_capture_session_id,
               last_processed_id_before, last_processed_id_after,
               last_completed_window_end_before, last_completed_window_end_after,
               updated_at_before, updated_at_after, plan_sha256, plan_json,
               skipped_session_count, skipped_processable_session_count,
               approved_by, reason, repository_commit, database_path,
               backup_path, backup_sha256, created_at
        FROM packet_checkpoint_recoveries
        WHERE operation_id = ?
        """,
        (operation_id,),
    ).fetchone()


def _list_segment_feature_counts(
    connection: sqlite3.Connection,
    session_id: str,
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT pcsg.id AS segment_id,
               pcsg.window_start, pcsg.window_end, pcsg.status, pcsg.error_code,
               COUNT(pfl.id) AS feature_count
        FROM packet_capture_segments pcsg
        LEFT JOIN packet_feature_logs pfl ON pfl.capture_segment_id = pcsg.id
        JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
        WHERE pcs.session_id = ?
        GROUP BY pcsg.id, pcsg.window_start, pcsg.window_end,
                 pcsg.status, pcsg.error_code
        ORDER BY pcsg.window_start ASC, pcsg.id ASC
        """,
        (session_id,),
    ).fetchall()


def _last_segment_window_end(rows: Sequence[sqlite3.Row]) -> datetime | None:
    if not rows:
        return None
    return max(parse_db_utc(row["window_end"], "window_end") for row in rows)


def _live_resume_blocking_reasons(
    rows: Sequence[sqlite3.Row], first_window_start: datetime
) -> tuple[str, ...]:
    """Validate the complete observed RUNNING-session shape.

    A trailing READY suffix is an expected extractor backlog. Every observed
    window must still be contiguous and well formed, and terminal segments may
    not appear after that suffix has started.
    """
    expected = first_window_start
    ready_tail_started = False
    reasons: list[str] = []
    for row in rows:
        start = parse_db_utc(row["window_start"], "window_start")
        end = parse_db_utc(row["window_end"], "window_end")
        if start < expected:
            reasons.append("SEGMENT_BEFORE_OR_OVERLAPPING_PREFIX")
        elif start > expected:
            reasons.append("MISSING_WINDOW")
        if end != start + timedelta(seconds=10):
            reasons.append("INVALID_WINDOW_DURATION")

        status = str(row["status"])
        feature_count = int(row["feature_count"])
        if status == "FAILED" or row["error_code"] is not None:
            reasons.append("FAILED_OR_EXTRACTOR_ERROR")
        elif status in {"PROCESSED", "EMPTY"}:
            if ready_tail_started:
                reasons.append("TERMINAL_AFTER_READY_TAIL")
            if (status == "PROCESSED" and feature_count == 0) or (
                status == "EMPTY" and feature_count != 0
            ):
                reasons.append("FEATURE_COUNT_MISMATCH")
        elif status == "READY":
            ready_tail_started = True
            if feature_count != 0:
                reasons.append("FEATURE_COUNT_MISMATCH")

        expected = end
    return tuple(dict.fromkeys(reasons))


def calculate_packet_feature_readiness(
    connection: sqlite3.Connection,
    session_id: str,
) -> RecoverySessionReadiness | None:
    session = get_capture_session(connection, session_id)
    if session is None:
        return None
    raw_first = session["first_window_start"]
    if raw_first is None:
        return RecoverySessionReadiness(
            session_id,
            None,
            None,
            0,
            0,
            False,
            ("NO_FIRST_WINDOW",),
            ("NO_FIRST_WINDOW",),
        )

    first = parse_db_utc(raw_first, "first_window_start")
    expected = first
    ready_through: datetime | None = None
    segment_count = 0
    feature_row_count = 0
    consumed_segment_ids: list[int] = []
    blocking_reasons: list[str] = []
    rows = _list_segment_feature_counts(connection, session_id)
    for row in rows:
        start = parse_db_utc(row["window_start"], "window_start")
        if start < expected:
            blocking_reasons.append("SEGMENT_BEFORE_OR_OVERLAPPING_PREFIX")
            continue
        if start > expected:
            blocking_reasons.append("MISSING_WINDOW")
            break
        status = str(row["status"])
        count = int(row["feature_count"])
        if status not in {"PROCESSED", "EMPTY"} or row["error_code"] is not None:
            blocking_reasons.append("NON_TERMINAL_OR_ERROR")
            break
        if (status == "PROCESSED" and count == 0) or (
            status == "EMPTY" and count != 0
        ):
            blocking_reasons.append("FEATURE_COUNT_MISMATCH")
            break
        end = parse_db_utc(row["window_end"], "window_end")
        if end != start + timedelta(seconds=10):
            blocking_reasons.append("INVALID_WINDOW_DURATION")
            break
        segment_count += 1
        feature_row_count += count
        consumed_segment_ids.append(int(row["segment_id"]))
        ready_through = end
        expected = end

    last_end = _last_segment_window_end(rows)
    all_segment_ids = [int(row["segment_id"]) for row in rows]
    full_ready = (
        session["status"] == "COMPLETED"
        and ready_through is not None
        and ready_through == last_end
        and segment_count == len(rows)
        and consumed_segment_ids == all_segment_ids
        and len(consumed_segment_ids) == len(set(consumed_segment_ids))
        and not blocking_reasons
    )
    live_resume_reasons = _live_resume_blocking_reasons(rows, first)
    return RecoverySessionReadiness(
        session_id,
        first,
        ready_through,
        segment_count,
        feature_row_count,
        full_ready,
        tuple(blocking_reasons),
        live_resume_reasons,
    )
