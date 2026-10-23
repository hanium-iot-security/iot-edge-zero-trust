"""Pure SQLite planned-stop approvals and one-time Packet pair transitions.

The root-only CLI owns services, the shared locks, consistent backup and
BEGIN IMMEDIATE. No shutdown, filesystem access, checkpoint jump for MQTT or
Trust, score reset, or failure-recovery policy change occurs in this module.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sqlite3
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from edge.detection.checkpoint_repository import PHASE4_CHECKPOINT_KEYS
from edge.detection.phase4_time import format_db_utc, parse_db_utc, require_utc_window_boundary
from edge.packet.capture_policy import (
    CaptureEligibilitySegment, CapturePolicy, DEFAULT_CAPTURE_POLICY, is_capture_eligible,
)
from edge.packet.feature_evidence import packet_feature_evidence_matches


REQUIRED_CHECKPOINTS = tuple(item for item in PHASE4_CHECKPOINT_KEYS if item[0] != "mqtt_if")
PACKET_DETECTORS = ("packet_rule", "packet_if")
PLAN_SCHEMA_VERSION = "planned-maintenance-resume-v1"
OPERATIONS_TABLE = "planned_maintenance_operations"
AUDIT_TABLE = "planned_maintenance_resumes"
APPROVAL_LIFETIME = timedelta(days=7)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MIGRATION_010_SCHEMA_SHA256 = "38cd62fc678e30ea9b43b6c873147d43fb5e79aba5e585326bb79d185a93838c"


class PlannedMaintenanceError(ValueError):
    """Keep the approval/readiness gate closed; strict failure recovery applies."""


def _require(value, reason):
    if not value:
        raise PlannedMaintenanceError(reason)


def _rows(db, sql, params=None):
    if isinstance(db, sqlite3.Connection):
        cursor = db.execute(sql, params or {})
        fields = [column[0] for column in cursor.description]
        return [dict(zip(fields, row)) for row in cursor.fetchall()]
    return [dict(row) for row in db.execute(text(sql), params or {}).mappings()]


def _one(db, sql, params=None):
    rows = _rows(db, sql, params)
    _require(len(rows) <= 1, "Ambiguous maintenance evidence.")
    return rows[0] if rows else None


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _time(value):
    if isinstance(value, datetime):
        _require(value.tzinfo is not None and value.utcoffset() == timedelta(0), "UTC time is required.")
    try:
        parsed = parse_db_utc(value)
        rendered = format_db_utc(parsed)
    except (ValueError, TypeError) as exc:
        raise PlannedMaintenanceError("Whole-second UTC time is required.") from exc
    _require(isinstance(value, datetime) or value == rendered, "Canonical UTC timestamps are required.")
    return rendered


def _window(value):
    rendered = _time(value)
    try:
        require_utc_window_boundary(parse_db_utc(rendered), "maintenance boundary")
    except ValueError as exc:
        raise PlannedMaintenanceError("A UTC 10-second boundary is required.") from exc
    return rendered


def _uuid(value):
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise PlannedMaintenanceError("Canonical UUID identity is required.") from exc
    _require(str(parsed) == value and parsed.version == 4, "Canonical version-4 UUID identity is required.")
    return value


def _schema(db):
    row = _one(db, "SELECT name FROM schema_migrations WHERE version=10")
    _require(row and row["name"] == "planned_maintenance", "Migration 010 planned_maintenance is required.")
    objects = _rows(db, "SELECT type,name,sql FROM sqlite_master WHERE name LIKE '%planned_maintenance%' "
                    "AND sql IS NOT NULL ORDER BY type,name")
    normalized = [{**item, "sql": " ".join(item["sql"].split())} for item in objects]
    _require(_digest(normalized) == _MIGRATION_010_SCHEMA_SHA256,
             "Migration 010 schema/seal contract differs or required triggers are missing.")


@contextmanager
def _mutation(conn):
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction,
             "Caller must own a protected SQLite transaction.")
    conn.execute("SAVEPOINT planned_maintenance")
    try:
        yield
        conn.execute("RELEASE SAVEPOINT planned_maintenance")
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT planned_maintenance")
        conn.execute("RELEASE SAVEPOINT planned_maintenance")
        raise


def get_operation(db, operation_id):
    _schema(db)
    _uuid(operation_id)
    row = _one(db, f"SELECT * FROM {OPERATIONS_TABLE} WHERE operation_id=:id", {"id": operation_id})
    _require(row, "Planned maintenance operation does not exist.")
    return row


def _session(db, identity):
    _uuid(identity)
    row = _one(db, "SELECT * FROM packet_capture_sessions WHERE session_id=:id", {"id": identity})
    _require(row, "Bound Capture Session does not exist.")
    return row


def _required_specs(value):
    normalized = tuple(tuple(item) for item in value)
    supported = (set(REQUIRED_CHECKPOINTS), set(PHASE4_CHECKPOINT_KEYS))
    _require(len(normalized) == len(set(normalized)) and set(normalized) in supported,
             "All six canonical checkpoints (plus enabled MQTT IF) must participate.")
    return normalized


def _checkpoints(db, required=REQUIRED_CHECKPOINTS):
    result = {}
    for detector, source in required:
        row = _one(db, "SELECT * FROM detector_checkpoints WHERE detector_name=:detector AND source_table=:source",
                   {"detector": detector, "source": source})
        _require(row, f"Required checkpoint is missing: {detector}.")
        _window(row["last_completed_window_end"])
        last_id = row["last_processed_id"]
        _require(last_id is None or (isinstance(last_id, int) and last_id >= 0), "Invalid source checkpoint ID.")
        result[detector] = row
    return result


def _approved_source_gaps(db, segments):
    from edge.packet.segment_gap_recovery import approved_segment_gaps
    from edge.packet.confirmed_partial_capture import approved_partial_capture_gaps
    failed = [row for row in segments if row["status"] == "FAILED" and row["error_code"] == "PARTIAL_CAPTURE"]
    old = approved_segment_gaps(db, failed)
    partial = approved_partial_capture_gaps(db, failed)
    return {row["id"]: audit for row, prior, current in zip(failed, old, partial)
            if (audit := prior or current) is not None}


def _source_gap_metadata(segments, audits):
    result = []
    for segment in segments:
        if segment["status"] != "FAILED" and segment["error_code"] is None:
            continue
        audit = audits.get(segment["id"])
        _require(audit is not None, "Source Capture gap has no valid approved audit.")
        if audit.get("loss_kind") == "PARTIAL_CAPTURE":
            result.append({"segment_id": segment["id"], "audit_table": "packet_detection_gaps",
                           "loss_kind": "PARTIAL_CAPTURE", **{key: audit[key] for key in
                           ("id", "plan_sha256", "pcap_sha256", "diagnostics_sha256", "evidence_sha256")}})
        else:
            result.append({"segment_id": segment["id"], **{key: audit[key] for key in
                          ("id", "operation_id", "plan_sha256", "backup_sha256", "pcap_sha256")}})
    return result


def _source_gap_seal(db, session):
    failed = _rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id AND "
                   "(status='FAILED' OR error_code IS NOT NULL) ORDER BY window_start,id", {"id": session["id"]})
    return _source_gap_metadata(failed, _approved_source_gaps(db, failed))


def _verify_source_gap_seal(db, snapshot):
    if "audited_segment_gaps" in snapshot:
        _require(bool(snapshot["audited_segment_gaps"])
                 and snapshot["audited_segment_gaps"] == _source_gap_seal(db, snapshot["session"]),
                 "Sealed source gap audits changed.")


def _segments(db, session, policy, *, allow_ready=False, approved_gaps=None,
              feature_rows=None, segment_rows=None):
    start = _window(session["first_window_start"])
    rows = (segment_rows if segment_rows is not None else
            _rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id ORDER BY window_start,id",
                  {"id": session["id"]}))
    _require(rows, "Capture Session has no complete Packet evidence.")
    if feature_rows is None:
        feature_rows = _rows(db, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s "
                             "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id ORDER BY f.id",
                             {"id": session["id"]})
    by_segment = {}
    for feature in feature_rows:
        by_segment.setdefault(feature["capture_segment_id"], []).append(feature)
    for row in rows:
        _require(_window(row["window_start"]) == start, "Capture has a missing or overlapping Window.")
        end = _window(row["window_end"])
        _require(parse_db_utc(end) - parse_db_utc(start) == timedelta(seconds=10), "Invalid Capture Window.")
        _require(row["capture_interface"] == session["capture_interface"], "Capture interface changed.")
        features = by_segment.get(row["id"], [])
        if approved_gaps is not None and row["id"] in approved_gaps:
            _require(not features, "Audited failed Capture gained Packet Features.")
            start = end
            continue
        view_status = "PROCESSED" if allow_ready and row["status"] == "READY" else row["status"]
        eligible = is_capture_eligible(CaptureEligibilitySegment(
            view_status, row["error_code"], row["start_delay_seconds"], row["captured_duration_seconds"]), policy)
        _require(eligible.eligible and row["error_message"] is None and row["file_name"] is not None,
                 f"Capture is not healthy: {row['id']}:{eligible.exclusion_reason}.")
        _require(all(item["window_start"] == start and item["window_end"] == end for item in features),
                 "Packet Feature Window differs from its Capture.")
        _require((row["status"] == "PROCESSED" and bool(features))
                 or (row["status"] in ("EMPTY", "READY") and not features), "Capture/Feature status disagrees.")
        start = end
    return rows


def _source_snapshot(db, session, policy):
    features = _rows(db, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s ON s.id=f.capture_segment_id "
                     "WHERE s.capture_session_id=:id ORDER BY f.id", {"id": session["id"]})
    segments = _rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id ORDER BY window_start,id",
                     {"id": session["id"]})
    gaps = _approved_source_gaps(db, segments)
    segments = _segments(db, session, policy, feature_rows=features, segment_rows=segments, approved_gaps=gaps)
    result = {"session": session, "segment_count": len(segments), "segment_sha256": _digest(segments),
            "feature_count": len(features), "feature_sha256": _digest(features),
            "capture_policy": asdict(policy), "final_boundary": segments[-1]["window_end"]}
    sealed_gaps = _source_gap_metadata(segments, gaps)
    if sealed_gaps:
        result["audited_segment_gaps"] = sealed_gaps
    return result


def _no_old_pending(db, boundary):
    rows = _rows(db, "SELECT id FROM detection_events WHERE processed_at IS NULL AND "
                 "((analysis_window_end IS NOT NULL AND (unixepoch(analysis_window_end) IS NULL OR "
                 "unixepoch(analysis_window_end)<=unixepoch(:end))) OR "
                 "(analysis_window_end IS NULL AND (unixepoch(detected_at) IS NULL OR "
                 "unixepoch(detected_at)<=unixepoch(:end))) OR "
                 "(analysis_window_start IS NOT NULL AND unixepoch(analysis_window_start) IS NULL)) LIMIT 1",
                 {"end": boundary})
    _require(not rows, "Pre-maintenance Detection Events still await Trust processing.")


def _fully_drained(db, checkpoints, boundary, *, exact_boundaries=True):
    for detector, row in checkpoints.items():
        _require(parse_db_utc(row["last_completed_window_end"]) >= parse_db_utc(boundary),
                 f"Source processing is incomplete: {detector}.")
        if exact_boundaries or detector in PACKET_DETECTORS:
            _require(row["last_completed_window_end"] == boundary,
                     f"Checkpoint passed the source shutdown boundary: {detector}.")
        source = row["source_table"]
        if source == "detection_events":
            continue
        if source == "mqtt_logs":
            # SQLite rounds 19.999999 into the boundary second. Select that
            # second inclusively, then enforce the original precise timestamp.
            rows = _rows(db, "SELECT id,received_at FROM mqtt_logs WHERE id>:id AND "
                         "(unixepoch(received_at)<=unixepoch(:end) OR unixepoch(received_at) IS NULL)",
                         {"id": row["last_processed_id"] or 0, "end": boundary})
            try:
                pending = [item for item in rows if item["received_at"] is None
                           or parse_db_utc(item["received_at"], allow_subseconds=True) < parse_db_utc(boundary)]
            except (ValueError, TypeError) as exc:
                raise PlannedMaintenanceError("Unconsumed MQTT source has an invalid received_at.") from exc
            _require(not pending, f"Unconsumed pre-maintenance source rows: {detector}.")
            continue
        # Packet Rule consumes only INBOUND rows; its source ID need not match
        # Packet IF, which also consumes OUTBOUND rows without inferring on them.
        scope = " AND direction='INBOUND'" if detector == "packet_rule" and source == "packet_feature_logs" else ""
        pending = _one(db, f"SELECT MAX(id) AS last_id FROM {source} WHERE unixepoch(window_end)<=unixepoch(:end){scope}",
                       {"end": boundary})["last_id"]
        _require(pending is None or (row["last_processed_id"] is not None and row["last_processed_id"] >= pending),
                 f"Unconsumed pre-maintenance source rows: {detector}.")
    _no_old_pending(db, boundary)


def _no_gap_events(db, start, end):
    rows = _rows(db, "SELECT id FROM detection_events WHERE "
                 "(analysis_window_start IS NOT NULL AND analysis_window_end IS NOT NULL "
                 "AND unixepoch(analysis_window_start)<unixepoch(:end) "
                 "AND unixepoch(analysis_window_end)>unixepoch(:start)) OR "
                 "(analysis_window_start IS NULL AND analysis_window_end IS NOT NULL "
                 "AND unixepoch(analysis_window_end)>unixepoch(:start) "
                 "AND unixepoch(analysis_window_end)<=unixepoch(:end)) OR "
                 "(analysis_window_end IS NULL AND unixepoch(detected_at)>=unixepoch(:start) "
                 "AND unixepoch(detected_at)<unixepoch(:end)) LIMIT 1", {"start": start, "end": end})
    _require(not rows, "Existing Detection Events overlap planned downtime; strict recovery review is required.")


def request_stop(conn, *, approved_by, reason, source_session_id, source_boot_id,
                 required_checkpoints=REQUIRED_CHECKPOINTS, now):
    """Record approval while the exact source Session is still RUNNING."""
    with _mutation(conn):
        _schema(conn)
        now = _time(now)
        _uuid(source_boot_id)
        for value in (approved_by, reason):
            _require(isinstance(value, str) and bool(value.strip()), "Approval identity and reason are required.")
        normalized = _required_specs(required_checkpoints)
        session = _session(conn, source_session_id)
        running = _rows(conn, "SELECT session_id FROM packet_capture_sessions WHERE status='RUNNING'")
        _require(session["status"] == "RUNNING" and len(running) == 1 and running[0]["session_id"] == source_session_id,
                 "Only the approved source Capture Session may be RUNNING.")
        _require(parse_db_utc(session["started_at"]) <= parse_db_utc(now), "Request precedes source Session.")
        _require(not _rows(conn, f"SELECT operation_id FROM {OPERATIONS_TABLE} WHERE status IN ('REQUESTED','READY')"),
                 "Another planned maintenance approval is active.")
        operation_id = str(uuid4())
        conn.execute(f"INSERT INTO {OPERATIONS_TABLE}(operation_id,status,approved_by,reason,source_session_id,source_boot_id,"
                     "required_checkpoints_json,requested_at) VALUES (:id,'REQUESTED',:by,:reason,:sid,:boot,:required,:now)",
                     {"id": operation_id, "by": approved_by, "reason": reason, "sid": source_session_id,
                      "boot": source_boot_id, "required": _json(normalized), "now": now})
        return get_operation(conn, operation_id)


def cancel_stop(conn, operation_id, *, reason, now):
    """Invalidate an incomplete stop; it can never authorize a future restart."""
    with _mutation(conn):
        row = get_operation(conn, operation_id)
        _require(isinstance(reason, str) and reason.strip(), "Cancellation reason is required.")
        now = _time(now)
        if row["status"] == "CANCELLED":
            return row
        _require(row["status"] in ("REQUESTED", "READY"), "Consumed approval cannot be cancelled.")
        conn.execute(f"UPDATE {OPERATIONS_TABLE} SET status='CANCELLED',cancelled_at=:now,cancellation_reason=:reason "
                     "WHERE operation_id=:id AND status=:before",
                     {"now": now, "reason": reason, "id": operation_id, "before": row["status"]})
        return get_operation(conn, operation_id)


def _sealed_source(operation):
    try:
        snapshot = json.loads(operation["source_snapshot_json"])
        cp_snapshot = json.loads(operation["checkpoint_snapshot_json"])
        policy = CapturePolicy(**snapshot["capture_policy"])
        required = _required_specs(json.loads(operation["required_checkpoints_json"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise PlannedMaintenanceError("Sealed source evidence is invalid.") from exc
    _require(snapshot["session"]["status"] == "COMPLETED"
             and snapshot["final_boundary"] == operation["source_final_boundary"] == operation["maintenance_start"],
             "Sealed source completion boundary is invalid.")
    _require(set(cp_snapshot) == {name for name, _ in required}, "Sealed checkpoint set is invalid.")
    _require(all(cp_snapshot[name]["detector_name"] == name and cp_snapshot[name]["source_table"] == table
                 for name, table in required), "Sealed checkpoint identities differ from required registry.")
    return snapshot, cp_snapshot, policy


def _bound_source(db, operation, *, verify_hashes=True):
    snapshot, sealed, policy = _sealed_source(operation)
    session = _session(db, operation["source_session_id"])
    _require(session == snapshot["session"], "Sealed source Session changed.")
    _verify_source_gap_seal(db, snapshot)
    if verify_hashes:
        current = _source_snapshot(db, session, policy)
        _require({key: value for key, value in snapshot.items() if key != "feature_sha256"}
                 == {key: value for key, value in current.items() if key != "feature_sha256"},
                 "Source Capture evidence changed after planned shutdown.")
        features = _rows(db, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s "
                         "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id ORDER BY f.id",
                         {"id": session["id"]})
        _require(packet_feature_evidence_matches(features, snapshot["feature_sha256"]),
                 "Source Capture evidence changed after planned shutdown.")
    return snapshot, sealed, policy


def _unchanged_checkpoints(db, sealed):
    current = _checkpoints(db, tuple((name, row["source_table"]) for name, row in sealed.items()))
    for name, before in sealed.items():
        after = current[name]
        if name in PACKET_DETECTORS:
            _require(after == before, "A Packet checkpoint changed since planned shutdown.")
        else:
            _require(parse_db_utc(after["last_completed_window_end"]) >= parse_db_utc(before["last_completed_window_end"])
                     and (before["last_processed_id"] is None or (after["last_processed_id"] is not None
                          and after["last_processed_id"] >= before["last_processed_id"])),
                     "A non-Packet checkpoint rewound after shutdown.")
    return current


def finalize_stop(conn, operation_id, *, now, capture_policy=DEFAULT_CAPTURE_POLICY):
    """Seal READY only after graceful Capture completion and six-stage drain."""
    with _mutation(conn):
        row = get_operation(conn, operation_id)
        now = _time(now)
        if row["status"] == "READY":
            _, sealed, _ = _bound_source(conn, row)
            _unchanged_checkpoints(conn, sealed)
            _no_old_pending(conn, row["source_final_boundary"])
            return row
        _require(row["status"] == "REQUESTED", "Only an unconsumed stop request may become READY.")
        session = _session(conn, row["source_session_id"])
        _require(session["status"] == "COMPLETED" and session["ended_at"] is not None,
                 "Source Session did not complete gracefully.")
        _require(not _rows(conn, "SELECT id FROM packet_capture_sessions WHERE status='RUNNING'"),
                 "Capture has not stopped.")
        snapshot = _source_snapshot(conn, session, capture_policy)
        boundary = snapshot["final_boundary"]
        _require(parse_db_utc(boundary) <= parse_db_utc(session["ended_at"]) <= parse_db_utc(now)
                 and parse_db_utc(row["requested_at"]) <= parse_db_utc(session["ended_at"]),
                 "Shutdown request/completion timing does not match.")
        cp_snapshot = _checkpoints(conn, _required_specs(json.loads(row["required_checkpoints_json"])))
        _fully_drained(conn, cp_snapshot, boundary)
        expires = format_db_utc(parse_db_utc(now) + APPROVAL_LIFETIME)
        conn.execute(f"UPDATE {OPERATIONS_TABLE} SET status='READY',ready_at=:now,expires_at=:expires,"
                     "source_final_boundary=:boundary,maintenance_start=:boundary,source_snapshot_json=:source,"
                     "checkpoint_snapshot_json=:cp WHERE operation_id=:id AND status='REQUESTED'",
                     {"now": now, "expires": expires, "boundary": boundary, "source": _json(snapshot),
                      "cp": _json(cp_snapshot), "id": operation_id})
        return get_operation(conn, operation_id)


def calculate_plan_sha256(plan):
    return _digest({key: value for key, value in plan.items() if key not in ("plan_sha256", "generated_at")})


def _target_evidence(db, operation, target_id, policy, *, prefix_rows=None, successor_session_id=None):
    target = _session(db, target_id)
    source = _session(db, operation["source_session_id"])
    running = _rows(db, "SELECT session_id FROM packet_capture_sessions WHERE status='RUNNING'")
    if prefix_rows is None:
        _require(successor_session_id is None and target["status"] == "RUNNING"
                 and len(running) == 1 and running[0]["session_id"] == target_id,
                 "The exact new Capture Session must be uniquely RUNNING.")
    else:
        _require(target["status"] == "FAILED" and len(running) == 1
                 and running[0]["session_id"] == successor_session_id,
                 "Failed-prefix recovery requires the exact unique RUNNING successor.")
    _require(target["id"] > source["id"] and target["capture_interface"] == source["capture_interface"],
             "Target must be a new Session on the same capture interface.")
    _require(not _rows(db, "SELECT id FROM packet_capture_sessions WHERE id>:source AND id<:target",
                      {"source": source["id"], "target": target["id"]}),
             "An unapproved intervening Capture Session cannot be skipped.")
    boundary = _window(target["first_window_start"])
    _require(parse_db_utc(target["started_at"]) >= parse_db_utc(operation["ready_at"])
             and parse_db_utc(boundary) >= parse_db_utc(target["started_at"])
             and parse_db_utc(boundary) > parse_db_utc(operation["source_final_boundary"]),
             "Target begins before completed planned shutdown.")
    _require(target["capture_gap_start"] == operation["source_final_boundary"]
             and target["capture_gap_end"] == boundary, "Target gap does not bind the planned shutdown boundary.")
    segments = _segments(db, target, policy, allow_ready=prefix_rows is None, segment_rows=prefix_rows)
    empty_prefix = []
    for first in segments:
        if first["status"] != "EMPTY":
            break
        empty_prefix.append(first)
    _require(first["status"] == "PROCESSED", "The first full new Packet Feature is not ready.")
    features = _rows(db, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id",
                     {"id": first["id"]})
    _require(any(item["packet_count"] > 0 for item in features), "The first new Packet Feature has no traffic.")
    _require(not _rows(db, "SELECT id FROM packet_capture_segments WHERE unixepoch(window_start)<unixepoch(:end) "
                      "AND unixepoch(window_end)>unixepoch(:start)",
                      {"start": operation["source_final_boundary"], "end": boundary}),
             "Processable or failed Capture evidence exists inside the planned downtime.")
    _require(not _rows(db, "SELECT id FROM packet_feature_logs WHERE unixepoch(window_start)<unixepoch(:end) "
                      "AND unixepoch(window_end)>unixepoch(:start)",
                      {"start": operation["source_final_boundary"], "end": boundary}),
             "Packet Features inside planned downtime cannot be skipped.")
    evidence = {"session": {key: target[key] for key in ("id", "session_id", "capture_interface", "started_at", "first_window_start")},
                "segment": first, "features_sha256": _digest(features), "feature_count": len(features)}
    if empty_prefix:
        evidence["empty_prefix"] = empty_prefix
    return evidence


def inspect_resume(conn, operation_id, *, target_session_id, current_boot_id, time_synchronized, now,
                   verify_source_hashes=True):
    """Read-only, append-tolerant plan; no blind skip and no approval for crashes."""
    row = get_operation(conn, operation_id)
    now = _time(now)
    _require(row["status"] == "READY", "A sealed, unconsumed READY approval is required.")
    _require(parse_db_utc(row["ready_at"]) <= parse_db_utc(now) <= parse_db_utc(row["expires_at"]),
             "Planned shutdown approval expired or time moved backwards.")
    _require(time_synchronized is True, "System time is not synchronized.")
    _uuid(current_boot_id)
    _require(current_boot_id != row["source_boot_id"], "Same-boot restart requires strict recovery.")
    snapshot, sealed, policy = _bound_source(conn, row, verify_hashes=verify_source_hashes)
    current = _unchanged_checkpoints(conn, sealed)
    _fully_drained(conn, current, row["source_final_boundary"], exact_boundaries=False)
    first = _target_evidence(conn, row, target_session_id, policy)
    boundary = first["session"]["first_window_start"]
    _no_gap_events(conn, row["source_final_boundary"], boundary)
    _require(parse_db_utc(first["segment"]["window_end"]) <= parse_db_utc(now), "First target Feature is from the future.")
    plan = {"schema_version": PLAN_SCHEMA_VERSION, "can_execute": True, "operation_id": operation_id,
            "approved_by": row["approved_by"], "reason": row["reason"], "source_session_id": row["source_session_id"],
            "source_boot_id": row["source_boot_id"], "target_session_id": target_session_id,
            "target_boot_id": current_boot_id, "maintenance_start": row["source_final_boundary"],
            "maintenance_end": boundary, "ready_at": row["ready_at"], "expires_at": row["expires_at"],
            "source_snapshot": snapshot, "checkpoint_snapshot": sealed, "first_target_evidence": first,
            "checkpoints": {name: {"before": current[name], "after": {
                **current[name], "last_completed_window_end": boundary, "updated_at": boundary}}
                for name in PACKET_DETECTORS}, "generated_at": now}
    plan["plan_sha256"] = calculate_plan_sha256(plan)
    return plan


def _verify_plan(plan):
    _require(isinstance(plan, Mapping) and plan.get("schema_version") == PLAN_SCHEMA_VERSION,
             "Invalid planned resume schema.")
    _require(plan.get("plan_sha256") == calculate_plan_sha256(plan), "Planned resume SHA256 mismatch.")
    _require(plan.get("can_execute") is True, "Plan is not executable.")
    _require(set(plan.get("checkpoints", {})) == set(PACKET_DETECTORS), "Both Packet transitions are required.")
    for key in ("operation_id", "source_session_id", "target_session_id", "source_boot_id", "target_boot_id"):
        _uuid(plan.get(key))
    _require(plan["source_boot_id"] != plan["target_boot_id"], "Resume boot differs from shutdown boot.")
    _require(parse_db_utc(_window(plan["maintenance_start"])) < parse_db_utc(_window(plan["maintenance_end"])),
             "Maintenance exclusion must be a positive interval.")


def apply_resume(conn, plan, *, now, backup_path, backup_sha256):
    _require("failed_prefix_recovery" not in plan, "Use the explicit failed-prefix recovery command.")
    return _apply_resume(conn, plan, now=now, backup_path=backup_path,
                         backup_sha256=backup_sha256, inspect=inspect_resume)


def _apply_resume(conn, plan, *, now, backup_path, backup_sha256, inspect):
    """Atomically consume approval, update both Packet boundaries and add audit.

Normal tail appends do not invalidate the plan. The stopped source, current
Packet pair, first target Window and live continuity are revalidated under the
caller write transaction. A committed retry returns the same audit only.
"""
    with _mutation(conn):
        _verify_plan(plan)
        now = _time(now)
        _require(isinstance(backup_path, str) and Path(backup_path).is_absolute(), "Absolute backup path is required.")
        _require(isinstance(backup_sha256, str) and _HEX64.fullmatch(backup_sha256), "Verified backup SHA256 is required.")
        row = get_operation(conn, plan["operation_id"])
        if row["status"] == "RESUMED":
            audit = _validated_audit(conn, row)
            _require(audit["plan_sha256"] == plan["plan_sha256"], "Consumed approval belongs to another plan.")
            return audit
        current = inspect(conn, plan["operation_id"], target_session_id=plan["target_session_id"],
                                 current_boot_id=plan["target_boot_id"], time_synchronized=True, now=now,
                                 verify_source_hashes=False)
        _require(current["plan_sha256"] == plan["plan_sha256"], "Bound resume evidence changed after inspection.")
        changes = conn.total_changes
        for name in PACKET_DETECTORS:
            before, after = plan["checkpoints"][name]["before"], plan["checkpoints"][name]["after"]
            changed = conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=:end,updated_at=:end "
                                   "WHERE detector_name=:name AND source_table='packet_feature_logs' "
                                   "AND last_processed_id IS :id AND last_completed_window_end=:start AND updated_at=:updated",
                                   {"end": after["last_completed_window_end"], "name": name,
                                    "id": before["last_processed_id"], "start": before["last_completed_window_end"],
                                    "updated": before["updated_at"]})
            _require(changed.rowcount == 1, "Conditional Packet checkpoint update failed.")
        conn.execute(f"UPDATE {OPERATIONS_TABLE} SET status='RESUMED',target_session_id=:target,target_boot_id=:boot,"
                     "maintenance_end=:end,resumed_at=:now WHERE operation_id=:id AND status='READY'",
                     {"target": plan["target_session_id"], "boot": plan["target_boot_id"], "end": plan["maintenance_end"],
                      "now": now, "id": plan["operation_id"]})
        conn.execute(f"INSERT INTO {AUDIT_TABLE}(operation_id,target_session_id,target_boot_id,plan_sha256,plan_json,"
                     "backup_path,backup_sha256,resumed_at) VALUES (:id,:target,:boot,:sha,:plan,:path,:backup,:now)",
                     {"id": plan["operation_id"], "target": plan["target_session_id"], "boot": plan["target_boot_id"],
                      "sha": plan["plan_sha256"], "plan": _json(plan), "path": backup_path, "backup": backup_sha256, "now": now})
        _require(conn.total_changes - changes == 4, "Resume must change exactly two checkpoints, one approval and one audit.")
        _require(not conn.execute("PRAGMA foreign_key_check").fetchall(), "Foreign-key verification failed.")
        return _validated_audit(conn, get_operation(conn, plan["operation_id"]), check_current_checkpoints=True)


def _absolute_evidence_path(value):
    """A copied audit records its source host's path; no local file is opened here."""
    return isinstance(value, str) and (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())


def _validated_audit(db, operation, *, check_current_checkpoints=False):
    _require(operation["status"] == "RESUMED", "Maintenance is not RESUMED.")
    audit = _one(db, f"SELECT * FROM {AUDIT_TABLE} WHERE operation_id=:id", {"id": operation["operation_id"]})
    _require(audit, "Planned resume audit is missing.")
    plan = json.loads(audit["plan_json"])
    _verify_plan(plan)
    for key in ("operation_id", "approved_by", "reason", "source_session_id", "source_boot_id", "target_session_id",
                "target_boot_id", "maintenance_start", "maintenance_end", "ready_at", "expires_at"):
        _require(operation[key] == plan[key], "Approval and audit plan binding differs.")
    for key in ("operation_id", "target_session_id", "target_boot_id", "plan_sha256"):
        _require(audit[key] == plan[key], "Resume audit differs from plan.")
    _require(audit["resumed_at"] == operation["resumed_at"] and _HEX64.fullmatch(audit["backup_sha256"])
             and _absolute_evidence_path(audit["backup_path"]), "Resume backup/completion evidence is invalid.")
    source, sealed, _ = _sealed_source(operation)
    _require(_session(db, operation["source_session_id"]) == source["session"], "Sealed source Session changed.")
    _verify_source_gap_seal(db, source)
    _require(parse_db_utc(operation["ready_at"]) <= parse_db_utc(operation["resumed_at"]) <= parse_db_utc(operation["expires_at"]),
             "Resume occurred outside its authorized lifetime.")
    _require(source == plan["source_snapshot"] and sealed == plan["checkpoint_snapshot"], "Sealed plan source changed.")
    first = plan["first_target_evidence"]
    target = _session(db, plan["target_session_id"])
    _require(all(target[key] == value for key, value in first["session"].items()), "First target Session binding changed.")
    segment = _one(db, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": first["segment"]["id"]})
    features = _rows(db, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id",
                     {"id": first["segment"]["id"]})
    _require(segment == first["segment"] and packet_feature_evidence_matches(features, first["features_sha256"])
             and len(features) == first["feature_count"], "First target Packet evidence changed.")
    empty_prefix = first.get("empty_prefix", [])
    if empty_prefix:
        prefix = _rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:session "
                       "AND window_start<:ready ORDER BY window_start,id",
                       {"session": target["id"], "ready": segment["window_start"]})
        _require(prefix == empty_prefix and prefix[0]["window_start"] == target["first_window_start"]
                 and all(item["status"] == "EMPTY" for item in prefix), "First target EMPTY prefix changed.")
        prefix_features = _rows(db, "SELECT f.id FROM packet_feature_logs f JOIN packet_capture_segments s "
                               "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:session "
                               "AND s.window_start<:ready LIMIT 1",
                               {"session": target["id"], "ready": segment["window_start"]})
        _require(not prefix_features, "First target EMPTY prefix gained Packet Features.")
    else:
        _require(segment["window_start"] == target["first_window_start"], "First target Packet boundary changed.")
    if "failed_prefix_recovery" in plan:
        from edge.maintenance.prefix_recovery import validate_prefix_audit
        validate_prefix_audit(db, operation, plan)
    current = (_checkpoints(db, tuple((name, row["source_table"]) for name, row in sealed.items()))
               if check_current_checkpoints else None)
    for name in PACKET_DETECTORS:
        before, after = plan["checkpoints"][name]["before"], plan["checkpoints"][name]["after"]
        _require(before == sealed[name] and before["last_processed_id"] == after["last_processed_id"]
                 and before["last_completed_window_end"] == plan["maintenance_start"]
                 and after == {**before, "last_completed_window_end": plan["maintenance_end"],
                               "updated_at": plan["maintenance_end"]}, "Invalid Packet transition binding.")
        if current is None:
            continue
        actual = current[name]
        _require(parse_db_utc(actual["last_completed_window_end"]) >= parse_db_utc(plan["maintenance_end"])
                 and (before["last_processed_id"] is None or (actual["last_processed_id"] is not None
                      and actual["last_processed_id"] >= before["last_processed_id"])), "Packet checkpoint rewound after resume.")
        if actual["last_completed_window_end"] == plan["maintenance_end"]:
            _require(actual == after, "Packet boundary differs from the committed pair.")
    return {**audit, "source_final_boundary": plan["maintenance_start"],
            "maintenance_start": plan["maintenance_start"], "maintenance_end": plan["maintenance_end"],
            "window_start": plan["maintenance_start"], "window_end": plan["maintenance_end"],
            "checkpoints": plan["checkpoints"], "boundary": parse_db_utc(plan["maintenance_end"])}


def inspect_prefix_recovery(conn, operation_id, **kwargs):
    from edge.maintenance.prefix_recovery import inspect_prefix_recovery as inspect
    return inspect(conn, operation_id, **kwargs)


def apply_prefix_recovery(conn, plan, **kwargs):
    from edge.maintenance.prefix_recovery import apply_prefix_recovery as apply
    return apply(conn, plan, **kwargs)


def check_prefix_drain(conn, operation_id):
    from edge.maintenance.prefix_recovery import check_prefix_drain as check
    return check(conn, operation_id)


def get_resume_audit(db, operation_id, *, check_current_checkpoints=True):
    """Read-only committed result for response-loss/restart verification."""
    return _validated_audit(db, get_operation(db, operation_id),
                            check_current_checkpoints=check_current_checkpoints)


def approved_intervals(db):
    """Validated RESUMED exclusions, with cheap immutable audit/identity checks.

Absent migration returns no exclusions. Corrupt persisted approvals raise;
callers must hold processing/export rather than silently include suspect data.
    Entire stopped Session hashes are checked at finalize/inspect/apply, not in
    each producer iteration. Exclusions remain valid after later target failures.
"""
    if not _one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=:name", {"name": OPERATIONS_TABLE}):
        return []
    _schema(db)
    rows = _rows(db, f"SELECT * FROM {OPERATIONS_TABLE} WHERE status='RESUMED' ORDER BY maintenance_start,operation_id")
    result = []
    for row in rows:
        audit = _validated_audit(db, row)
        if result:
            _require(parse_db_utc(result[-1]["window_end"]) <= parse_db_utc(audit["window_start"]),
                     "Planned maintenance exclusions overlap.")
        result.append(audit)
    return result


def get_processing_cutoff(db):
    """Read-only live producer cap while a bound stop request is active.

    REQUESTED follows the source's latest finished Capture Window while the
    current tcpdump Window finishes. READY freezes its sealed final boundary.
    No existing processing checkpoint is ever moved backwards by this helper.
    An unexpected source failure raises instead of making a gap approved.
    """
    if not _one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=:name", {"name": OPERATIONS_TABLE}):
        return None
    _schema(db)
    rows = _rows(db, f"SELECT * FROM {OPERATIONS_TABLE} WHERE status IN ('REQUESTED','READY')")
    _require(len(rows) <= 1, "Multiple planned stop approvals are active.")
    if not rows:
        return None
    operation = rows[0]
    session = _session(db, operation["source_session_id"])
    if operation["status"] == "READY":
        _require(session["status"] == "COMPLETED", "READY source is no longer COMPLETED.")
        _bound_source(db, operation, verify_hashes=False)
        return parse_db_utc(_window(operation["source_final_boundary"]))
    _require(session["status"] in ("RUNNING", "COMPLETED"), "Requested source Session failed.")
    segments = _rows(db, "SELECT * FROM packet_capture_segments "
                     "WHERE capture_session_id=:id ORDER BY window_start,id", {"id": session["id"]})
    if session["first_window_start"] is None:
        return None
    approved_gaps = _approved_source_gaps(db, segments)
    boundary = _window(session["first_window_start"])
    for segment in segments:
        _require(segment["window_start"] == boundary
                 and ((segment["status"] != "FAILED" and segment["error_code"] is None)
                      or segment["id"] in approved_gaps),
                 "Requested source has an unapproved Capture gap.")
        end = _window(segment["window_end"])
        _require(parse_db_utc(end) - parse_db_utc(boundary) == timedelta(seconds=10), "Malformed source Capture Window.")
        boundary = end
    return parse_db_utc(boundary)


def resolve_planned_transition(db, boundary, packet_pair):
    """Resolve only the exact initial approved pair, without swallowing faults."""
    try:
        boundary = _window(boundary)
        pair_rows = list(packet_pair.values()) if isinstance(packet_pair, Mapping) else list(packet_pair)
        pair = {item["detector_name"]: dict(item) for item in pair_rows}
        _require(len(pair_rows) == 2 and set(pair) == set(PACKET_DETECTORS), "Both current Packet checkpoints are required.")
        _require(pair == {name: _checkpoints(db)[name] for name in PACKET_DETECTORS}, "Supplied Packet pair is stale.")
        valid = [audit for audit in approved_intervals(db) if audit["window_end"] == boundary
                 and all(pair[name] == audit["checkpoints"][name]["after"] for name in PACKET_DETECTORS)]
        if len(valid) != 1:
            return None
        _bound_source(db, get_operation(db, valid[0]["operation_id"]), verify_hashes=False)
        return valid[0]
    except (PlannedMaintenanceError, sqlite3.Error, SQLAlchemyError, ValueError, TypeError, KeyError):
        return None
