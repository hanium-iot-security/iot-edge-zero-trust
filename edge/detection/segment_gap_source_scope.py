"""Frozen recovery inputs with an explicit, append-only live producer tail.

Callers provide an existing consistent read transaction or a write transaction.
This module neither writes rows nor admits arbitrary data-version changes.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import PurePath

from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_window_boundary
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible


EXECUTION_MODE = "source-appends-v1"
_APPEND_TABLES = ("packet_capture_segments", "packet_feature_logs", "mqtt_logs", "feature_logs", "gateway_metrics")


def _sha(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _digest(connection, query: str, params=()) -> dict:
    cursor = connection.execute(query, params)
    digest = hashlib.sha256()
    digest.update(json.dumps([column[0] for column in cursor.description]).encode())
    count = 0
    for row in cursor:
        # raw_payload is a BLOB on the deployed schema. Encode its bytes without
        # printing or loading historical inputs into the approval document.
        values = [{"bytes_hex": value.hex()} if isinstance(value, bytes) else value for value in row]
        digest.update(json.dumps(values, separators=(",", ":"), ensure_ascii=False,
                                 allow_nan=False).encode())
        digest.update(b"\n")
        count += 1
    return {"count": count, "sha256": digest.hexdigest()}


def _schema(connection) -> dict:
    return _digest(connection, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")


def _tables(connection) -> list[str]:
    return [row[0] for row in connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name!='sqlite_sequence' ORDER BY name")]


def _protected(connection, scope: dict) -> dict:
    protected = {}
    high_water_marks = scope["high_water_marks"]
    for table in _tables(connection):
        quoted = _identifier(table)
        if table == "devices":
            columns = [row[1] for row in connection.execute("PRAGMA table_info(devices)")
                       if row[1] != "last_seen_at"]
            query, params = f"SELECT {','.join(map(_identifier, columns))} FROM devices ORDER BY device_id", ()
        elif table == "packet_capture_segments":
            query, params = ("SELECT * FROM packet_capture_segments WHERE capture_session_id=? AND id<=? ORDER BY id",
                             (scope["capture_session_pk"], high_water_marks[table]))
        elif table == "packet_feature_logs":
            query, params = ("SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s ON s.id=f.capture_segment_id "
                             "WHERE s.capture_session_id=? AND f.id<=? ORDER BY f.id",
                             (scope["capture_session_pk"], high_water_marks[table]))
        elif table in {"mqtt_logs", "feature_logs"}:
            query, params = (f"SELECT * FROM {quoted} WHERE id>=? AND id<=? ORDER BY id",
                             (scope["mqtt_input_low_water_marks"][table], high_water_marks[table]))
        elif table in _APPEND_TABLES:
            query, params = f"SELECT * FROM {quoted} WHERE id<=? ORDER BY id", (high_water_marks[table],)
        else:
            query, params = f"SELECT * FROM {quoted} ORDER BY rowid", ()
        protected[table] = _digest(connection, query, params)
    return protected


def _global_guards(connection, scope: dict) -> dict:
    bounds = (scope["recovery_input_start"], scope["recovery_input_end"])
    return {
        "failed_segments": _digest(connection, "SELECT * FROM packet_capture_segments "
                                   "WHERE status='FAILED' OR error_code IS NOT NULL OR error_message IS NOT NULL ORDER BY id"),
        "overlap_segments": _digest(connection, "SELECT * FROM packet_capture_segments "
                                    "WHERE unixepoch(window_end)>unixepoch(?) AND unixepoch(window_start)<unixepoch(?) ORDER BY id", bounds),
        "overlap_features": _digest(connection, "SELECT * FROM packet_feature_logs "
                                    "WHERE unixepoch(window_end)>unixepoch(?) AND unixepoch(window_start)<unixepoch(?) ORDER BY id", bounds),
    }


def build_source_scope(connection: sqlite3.Connection, plan: dict, *, capture_policy: CapturePolicy) -> dict:
    if not connection.in_transaction:
        raise ValueError("source scope requires a consistent transaction")
    session = connection.execute("SELECT id,capture_interface FROM packet_capture_sessions WHERE session_id=?",
                                 (plan["capture_session_id"],)).fetchone()
    if session is None:
        raise ValueError("source scope capture session is missing")
    high_water_marks = {table: connection.execute(f"SELECT coalesce(max(id),0) FROM {table}").fetchone()[0]
                        for table in _APPEND_TABLES}
    mqtt_input_low_water_marks = {
        table: connection.execute(
            f"SELECT coalesce(min(id),?) FROM {table} WHERE unixepoch({column})>=unixepoch(?)",
            (high_water_marks[table] + 1, plan["window_start"]),
        ).fetchone()[0]
        for table, column in (("mqtt_logs", "received_at"), ("feature_logs", "window_end"))
    }
    tail_start = connection.execute("SELECT max(window_end) FROM packet_capture_segments WHERE capture_session_id=?",
                                    (session[0],)).fetchone()[0]
    scope = {"schema_version": EXECUTION_MODE, "capture_session_pk": session[0],
             "capture_interface": session[1], "tail_start": tail_start,
             "capture_policy": asdict(capture_policy),
             "recovery_input_start": plan["window_start"],
             "recovery_input_end": plan["window_end"],
             "mqtt_input_low_water_marks": mqtt_input_low_water_marks,
             "high_water_marks": high_water_marks, "schema": _schema(connection)}
    scope["protected"] = _protected(connection, scope)
    scope["global_guards"] = _global_guards(connection, scope)
    scope["scope_sha256"] = _sha(scope)
    return scope


def validate_source_scope_envelope(scope: dict) -> None:
    required = {"schema_version", "capture_session_pk", "capture_interface", "tail_start",
                "capture_policy",
                "recovery_input_start", "recovery_input_end", "mqtt_input_low_water_marks", "high_water_marks",
                "schema", "protected", "global_guards", "scope_sha256"}
    if not isinstance(scope, dict) or set(scope) != required or scope.get("schema_version") != EXECUTION_MODE:
        raise ValueError("source scope envelope is invalid")
    if scope["scope_sha256"] != _sha({key: value for key, value in scope.items() if key != "scope_sha256"}):
        raise ValueError("source scope SHA256 mismatch")
    marks = scope["high_water_marks"]
    if not isinstance(marks, dict) or set(marks) != set(_APPEND_TABLES) or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in marks.values()):
        raise ValueError("source scope high-water marks are invalid")
    lower = scope["mqtt_input_low_water_marks"]
    if not isinstance(lower, dict) or set(lower) != {"mqtt_logs", "feature_logs"} or any(
            not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= marks[table] + 1
            for table, value in lower.items()):
        raise ValueError("source scope input low-water marks are invalid")
    policy = scope["capture_policy"]
    if not isinstance(policy, dict) or set(policy) != {
            "max_start_delay_seconds", "minimum_duration_seconds", "epsilon_seconds", "version"}:
        raise ValueError("source scope requires the complete configured Capture policy")
    CapturePolicy(**policy)
    if (not isinstance(scope["capture_session_pk"], int) or isinstance(scope["capture_session_pk"], bool)
            or scope["capture_session_pk"] <= 0 or not isinstance(scope["capture_interface"], str)
            or not scope["capture_interface"].strip() or not isinstance(scope["protected"], dict)):
        raise ValueError("source scope capture binding is invalid")
    for key in ("tail_start", "recovery_input_start", "recovery_input_end"):
        parsed = require_utc_window_boundary(parse_db_utc(scope[key]), key)
        if format_db_utc(parsed) != scope[key]:
            raise ValueError("source scope requires canonical UTC boundaries")


def verify_source_scope(connection: sqlite3.Connection, scope: dict) -> None:
    validate_source_scope_envelope(scope)
    if not connection.in_transaction:
        raise ValueError("source scope verification requires a consistent transaction")
    marks = scope["high_water_marks"]
    if (_schema(connection) != scope["schema"] or _protected(connection, scope) != scope["protected"]
            or _global_guards(connection, scope) != scope["global_guards"]):
        raise ValueError("protected source scope changed since approval")
    # Every new segment must be a contiguous, healthy ten-second tail in the
    # same Capture/Interface. A new failure never gets covered by this approval.
    expected = scope["tail_start"]
    capture_policy = CapturePolicy(**scope["capture_policy"])
    for row in connection.execute(
            "SELECT capture_session_id,capture_interface,window_start,window_end,status,error_code,error_message,"
            "file_name,start_delay_seconds,captured_duration_seconds,"
            "unixepoch(window_end)-unixepoch(window_start) "
            "FROM packet_capture_segments WHERE id>? ORDER BY window_start,id", (marks["packet_capture_segments"],)):
        duration = row[10]
        if (row[0] != scope["capture_session_pk"] or row[1] != scope["capture_interface"]
                or row[2] != expected or duration != 10 or row[4] not in {"READY", "PROCESSED", "EMPTY"}
                or row[5] is not None or row[6] is not None or not isinstance(row[7], str)
                or not row[7].strip() or PurePath(row[7]).name != row[7] or not row[7].endswith(".pcap")):
            raise ValueError("new Packet capture is outside the approved normal tail")
        for value in (row[2], row[3]):
            boundary = require_utc_window_boundary(parse_db_utc(value), "normal tail")
            if format_db_utc(boundary) != value:
                raise ValueError("normal tail requires canonical UTC boundaries")
        # READY is a captured file awaiting extraction. Test its capture quality
        # as a PROCESSED view without updating the row or making Features ready.
        eligibility = is_capture_eligible(CaptureEligibilitySegment(
            status="PROCESSED" if row[4] == "READY" else row[4], error_code=row[5],
            start_delay_seconds=row[8], captured_duration_seconds=row[9],
        ), capture_policy)
        if not eligibility.eligible:
            raise ValueError(f"new Packet capture is not eligible: {eligibility.exclusion_reason}")
        expected = row[3]
    invalid_features = connection.execute(
        "SELECT count(*) FROM packet_feature_logs f LEFT JOIN packet_capture_segments s ON s.id=f.capture_segment_id "
        "WHERE f.id>? AND (s.id IS NULL OR s.id<=? OR s.capture_session_id!=? OR s.status!='PROCESSED' "
        "OR s.error_code IS NOT NULL OR s.error_message IS NOT NULL OR f.window_start!=s.window_start "
        "OR f.window_end!=s.window_end)",
        (marks["packet_feature_logs"], marks["packet_capture_segments"], scope["capture_session_pk"]),
    ).fetchone()[0]
    if invalid_features:
        raise ValueError("new Packet Features are outside the approved normal tail")
    # Existing MQTT inputs in the approved LWM..HWM spans and all existing
    # metrics are frozen. Unrelated older MQTT history is outside this scope.
    # Producer timestamps precede their commits and are independent of Capture
    # boundaries. Admit delayed commits after the sealed recovery interval;
    # never admit backfill into that interval or use rows to justify lost PCAP.
    input_floor = parse_db_utc(scope["recovery_input_end"])
    for table, column in (("mqtt_logs", "received_at"), ("feature_logs", "window_start"),
                          ("gateway_metrics", "collected_at")):
        # SQLite unixepoch rounds 39.999999 up to second 40. Compare exact UTC
        # datetimes so a subsecond backfill cannot enter the sealed interval.
        for (value,) in connection.execute(f"SELECT {column} FROM {table} WHERE id>?", (marks[table],)):
            try:
                valid = parse_db_utc(value, allow_subseconds=True) >= input_floor
            except (ValueError, TypeError, OverflowError):
                valid = False
            if not valid:
                raise ValueError(f"new {table} input is outside the approved live tail")
