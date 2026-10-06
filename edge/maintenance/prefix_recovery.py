"""Explicit recovery of a healthy postboot prefix; never approves its failed tail."""
from __future__ import annotations

import json
import math
from datetime import timedelta

from edge.detection.phase4_time import parse_db_utc
from edge.maintenance import planned as p


def _ready_evidence(db, session, policy):
    segments = p._segments(db, session, policy, allow_ready=True)
    empty = []
    for segment in segments:
        if segment["status"] != "EMPTY":
            break
        empty.append(segment)
    p._require(segment["status"] == "PROCESSED", "Successor first Packet Feature is not ready.")
    features = p._rows(db, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id",
                       {"id": segment["id"]})
    p._require(any(row["packet_count"] > 0 for row in features), "Successor has no positive Packet Feature.")
    return {"session": {key: session[key] for key in
                        ("id", "session_id", "capture_interface", "started_at", "first_window_start")},
            "segment": segment, "empty_prefix": empty,
            "features_sha256": p._digest(features), "feature_count": len(features)}


def _proof(db, operation, target_id, successor_id, policy):
    target, successor = p._session(db, target_id), p._session(db, successor_id)
    p._require(target["status"] == "FAILED" and target["ended_at"] is not None,
               "Prefix target must be a closed FAILED Session.")
    rows = p._rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id ORDER BY window_start,id",
                   {"id": target["id"]})
    p._require(len(rows) >= 2, "Failed Session has no healthy prefix.")
    failure, prefix = rows[-1], rows[:-1]
    p._require(failure["status"] == "FAILED" and failure["error_code"] == "LATE_CAPTURE"
               and isinstance(failure["error_message"], str) and failure["error_message"].strip()
               and failure["capture_interface"] == target["capture_interface"] and failure["file_name"] is None
               and all(failure[key] is None for key in
                       ("actual_capture_started_at", "capture_stop_requested_at", "capture_process_exited_at"))
               and failure["captured_duration_seconds"] == 0 and failure["packet_count"] is None,
               "Only one uncaptured LATE_CAPTURE tail is supported.")
    delay = failure["start_delay_seconds"]
    p._require(isinstance(delay, (int, float)) and math.isfinite(delay)
               and delay > policy.max_start_delay_seconds + policy.epsilon_seconds,
               "Failed tail does not prove an out-of-policy capture start.")
    start, end = p._window(failure["window_start"]), p._window(failure["window_end"])
    p._require(parse_db_utc(end) - parse_db_utc(start) == timedelta(seconds=10)
               and prefix[-1]["window_end"] == start
               and parse_db_utc(start) <= parse_db_utc(target["ended_at"]) <= parse_db_utc(end),
               "Failed tail does not immediately follow the closed healthy prefix.")
    p._require(not p._rows(db, "SELECT id FROM packet_feature_logs WHERE capture_segment_id=:id",
                          {"id": failure["id"]}), "Failed tail must not contain Packet Features.")
    p._require(not p._rows(db, "SELECT id FROM packet_feature_logs WHERE window_start<:end AND window_end>:start",
                          {"start": start, "end": end}), "Packet Features overlap the uncaptured failed tail.")
    p._require(not p._rows(db, "SELECT id FROM packet_capture_segments WHERE capture_session_id!=:id "
                          "AND window_start<:end AND window_end>:start",
                          {"id": target["id"], "start": target["first_window_start"], "end": end}),
               "Another Session overlaps the failed Session prefix or tail.")
    p._require(successor["id"] > target["id"] and successor["capture_interface"] == target["capture_interface"]
               and successor["first_window_start"] == end
               and parse_db_utc(target["ended_at"]) <= parse_db_utc(successor["started_at"]) <= parse_db_utc(end)
               and not p._rows(db, "SELECT id FROM packet_capture_sessions WHERE id>:target AND id<:successor",
                               {"target": target["id"], "successor": successor["id"]}),
               "Successor must immediately follow the single failed tail.")
    p._segments(db, target, policy, segment_rows=prefix)
    features = p._rows(db, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s "
                       "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id ORDER BY f.id",
                       {"id": target["id"]})
    return target, successor, prefix, {
        "target_snapshot": {"session": target, "prefix_segment_count": len(prefix),
                            "prefix_segment_sha256": p._digest(prefix),
                            "feature_count": len(features), "feature_sha256": p._digest(features)},
        "failure": failure, "prefix_end": start, "successor_session_id": successor_id,
    }


def inspect_prefix_recovery(conn, operation_id, *, target_session_id, successor_session_id,
                            approved_by, reason, current_boot_id, time_synchronized, now,
                            verify_source_hashes=True):
    p._require(isinstance(approved_by, str) and approved_by.strip()
               and isinstance(reason, str) and reason.strip(), "Explicit recovery operator and reason are required.")
    row, now = p.get_operation(conn, operation_id), p._time(now)
    p._require(row["status"] == "READY", "A sealed, unconsumed READY approval is required.")
    p._require(parse_db_utc(row["ready_at"]) <= parse_db_utc(now) <= parse_db_utc(row["expires_at"]),
               "Planned shutdown approval expired or time moved backwards.")
    p._uuid(current_boot_id)
    p._require(time_synchronized is True and current_boot_id != row["source_boot_id"],
               "Recovery requires a synchronized, different boot.")
    snapshot, sealed, policy = p._bound_source(conn, row, verify_hashes=verify_source_hashes)
    current = p._unchanged_checkpoints(conn, sealed)
    p._fully_drained(conn, current, row["source_final_boundary"], exact_boundaries=False)
    target, successor, prefix, proof = _proof(conn, row, target_session_id, successor_session_id, policy)
    running = p._rows(conn, "SELECT session_id FROM packet_capture_sessions WHERE status='RUNNING'")
    p._require(successor["status"] == "RUNNING" and len(running) == 1
               and running[0]["session_id"] == successor_session_id
               and not p._rows(conn, "SELECT id FROM packet_capture_sessions WHERE id>:id", {"id": successor["id"]}),
               "The exact successor must be the unique latest RUNNING Session.")
    first = p._target_evidence(conn, row, target_session_id, policy,
                               prefix_rows=prefix, successor_session_id=successor_session_id)
    successor_evidence = _ready_evidence(conn, successor, policy)
    p._require(parse_db_utc(successor_evidence["segment"]["window_end"]) <= parse_db_utc(now),
               "Successor Feature is from the future.")
    boundary = first["session"]["first_window_start"]
    p._no_gap_events(conn, row["source_final_boundary"], boundary)
    proof.update(approved_by=approved_by.strip(), reason=reason.strip(), successor_evidence=successor_evidence)
    plan = {"schema_version": p.PLAN_SCHEMA_VERSION, "can_execute": True, "operation_id": operation_id,
            "approved_by": row["approved_by"], "reason": row["reason"], "source_session_id": row["source_session_id"],
            "source_boot_id": row["source_boot_id"], "target_session_id": target_session_id,
            "target_boot_id": current_boot_id, "maintenance_start": row["source_final_boundary"],
            "maintenance_end": boundary, "ready_at": row["ready_at"], "expires_at": row["expires_at"],
            "source_snapshot": snapshot, "checkpoint_snapshot": sealed, "first_target_evidence": first,
            "checkpoints": {name: {"before": current[name], "after": {
                **current[name], "last_completed_window_end": boundary, "updated_at": boundary}}
                for name in p.PACKET_DETECTORS}, "generated_at": now, "failed_prefix_recovery": proof}
    plan["plan_sha256"] = p.calculate_plan_sha256(plan)
    return plan


def apply_prefix_recovery(conn, plan, *, now, backup_path, backup_sha256):
    p._require(isinstance(plan.get("failed_prefix_recovery"), dict), "An explicit failed-prefix recovery plan is required.")
    proof = plan["failed_prefix_recovery"]

    def inspect(db, operation_id, **kwargs):
        return inspect_prefix_recovery(db, operation_id, successor_session_id=proof["successor_session_id"],
                                       approved_by=proof["approved_by"], reason=proof["reason"], **kwargs)

    return p._apply_resume(conn, plan, now=now, backup_path=backup_path,
                           backup_sha256=backup_sha256, inspect=inspect)


def validate_prefix_audit(db, operation, plan):
    recorded = plan["failed_prefix_recovery"]
    policy = p.CapturePolicy(**plan["source_snapshot"]["capture_policy"])
    _, successor, _, actual = _proof(db, operation, plan["target_session_id"], recorded["successor_session_id"], policy)
    p._require(all(actual[key] == recorded[key] for key in actual), "Failed-prefix recovery evidence changed.")
    evidence = recorded["successor_evidence"]
    p._require({key: successor[key] for key in evidence["session"]} == evidence["session"],
               "Successor identity changed after prefix recovery.")
    segment = p._one(db, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": evidence["segment"]["id"]})
    features = p._rows(db, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id",
                       {"id": evidence["segment"]["id"]})
    empty = p._rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id "
                    "AND window_start<:start ORDER BY window_start,id",
                    {"id": successor["id"], "start": evidence["segment"]["window_start"]})
    p._require(segment == evidence["segment"] and p._digest(features) == evidence["features_sha256"]
               and len(features) == evidence["feature_count"] and empty == evidence["empty_prefix"],
               "Successor readiness evidence changed after prefix recovery.")
    p._require(not p._rows(db, "SELECT f.id FROM packet_feature_logs f JOIN packet_capture_segments s "
                          "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id AND s.window_start<:start LIMIT 1",
                          {"id": successor["id"], "start": evidence["segment"]["window_start"]}),
               "Successor EMPTY prefix gained Packet Features.")


def check_prefix_drain(db, operation_id):
    audit = p.get_resume_audit(db, operation_id)
    plan = json.loads(audit["plan_json"])
    p._require("failed_prefix_recovery" in plan, "Operation is not an explicit failed-prefix recovery.")
    proof = plan["failed_prefix_recovery"]
    required = tuple((name, row["source_table"]) for name, row in plan["checkpoint_snapshot"].items())
    checkpoints = p._checkpoints(db, required)
    end = proof["prefix_end"]
    if any(parse_db_utc(row["last_completed_window_end"]) < parse_db_utc(end) for row in checkpoints.values()):
        return {"result": "WAIT", "reason": "Healthy prefix processing is incomplete.", "prefix_end": end}
    p._require(all(checkpoints[name]["last_completed_window_end"] == end for name in p.PACKET_DETECTORS),
               "Packet checkpoints must stop exactly before the unapproved failed tail.")
    p._fully_drained(db, checkpoints, end, exact_boundaries=False)
    session_id = proof["target_snapshot"]["session"]["id"]
    for name in p.PACKET_DETECTORS:
        direction = "AND f.direction='INBOUND' " if name == "packet_rule" else ""
        rows = p._rows(db, "SELECT MAX(f.id) AS id FROM packet_feature_logs f JOIN packet_capture_segments s "
                       "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id " + direction,
                       {"id": session_id})
        expected = rows[0]["id"]
        if expected is None:
            expected = plan["checkpoints"][name]["before"]["last_processed_id"]
        p._require(checkpoints[name]["last_processed_id"] == expected, "Healthy prefix source IDs have not been consumed.")
    return {"result": "PREFIX_DRAINED_RECOVERY_REQUIRED", "operation_id": operation_id,
            "prefix_end": end, "failed_segment_id": proof["failure"]["id"],
            "successor_session_id": proof["successor_session_id"], "checkpoints": checkpoints}
