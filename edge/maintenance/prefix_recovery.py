"""Explicit recovery of a healthy postboot prefix; never approves its failed tail."""
from __future__ import annotations

import json
import math
from datetime import timedelta

from edge.detection.phase4_time import parse_db_utc
from edge.maintenance import planned as p
from edge.packet.feature_evidence import packet_feature_evidence_matches
from edge.packet.confirmed_gaps import SESSION_FIELDS, validated_confirmed_gap_evidence


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


def _pair_proof(db, target_id, successor_id, policy):
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


def _proof(db, operation, target_id, successor_id, policy):
    """Preserve one failed-prefix proof, or bind exactly two adjacent failures."""
    target, successor = p._session(db, target_id), p._session(db, successor_id)
    intermediate = p._rows(db, "SELECT * FROM packet_capture_sessions WHERE id>:target AND id<:successor ORDER BY id",
                           {"target": target["id"], "successor": successor["id"]})
    p._require(len(intermediate) <= 1, "At most two closed FAILED Sessions are supported.")
    if not intermediate:
        return _pair_proof(db, target_id, successor_id, policy)
    middle = intermediate[0]
    target, _, prefix, proof = _pair_proof(db, target_id, middle["session_id"], policy)
    _, successor, _, child = _pair_proof(db, middle["session_id"], successor_id, policy)
    # An unrelated feature must not claim time in either preserved prefix, even
    # if its own Capture row is elsewhere. Failed-tail overlap is checked above.
    for session, pair in ((target, proof), (middle, child)):
        p._require(not p._rows(db, "SELECT id FROM packet_feature_logs WHERE "
                              "(capture_segment_id IS NULL OR capture_segment_id NOT IN "
                              "(SELECT id FROM packet_capture_segments WHERE capture_session_id=:id)) "
                              "AND unixepoch(window_start)<unixepoch(:end) "
                              "AND unixepoch(window_end)>unixepoch(:start)",
                              {"id": session["id"], "start": session["first_window_start"],
                               "end": pair["failure"]["window_end"]}),
                   "Unrelated Packet Features overlap a failed Session prefix or tail.")
    proof["intermediate_proofs"] = [child]
    proof["chain_adjacency"] = [
        {"source_session_id": session["session_id"], "source_ended_at": session["ended_at"],
         "failed_segment_id": pair["failure"]["id"], "failure_window_end": pair["failure"]["window_end"],
         "successor_session": {key: following[key] for key in
                               ("id", "session_id", "capture_interface", "started_at", "first_window_start")}}
        for session, pair, following in ((target, proof, middle), (middle, child, successor))
    ]
    proof["successor_session_id"] = successor_id
    return target, successor, prefix, proof


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


def _validate_failed_snapshot(db, actual, recorded):
    current_snapshot, sealed_snapshot = actual["target_snapshot"], recorded["target_snapshot"]
    p._require(all(actual[key] == recorded[key] for key in actual
                   if key not in ("target_snapshot", "intermediate_proofs"))
               and {key: value for key, value in current_snapshot.items() if key != "feature_sha256"}
               == {key: value for key, value in sealed_snapshot.items() if key != "feature_sha256"},
               "Failed-prefix recovery evidence changed.")
    target_features = p._rows(db, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s "
                             "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id ORDER BY f.id",
                             {"id": current_snapshot["session"]["id"]})
    p._require(packet_feature_evidence_matches(target_features, sealed_snapshot["feature_sha256"]),
               "Failed-prefix recovery evidence changed.")


def validate_prefix_audit(db, operation, plan):
    recorded = plan["failed_prefix_recovery"]
    policy = p.CapturePolicy(**plan["source_snapshot"]["capture_policy"])
    _, successor, _, actual = _proof(db, operation, plan["target_session_id"], recorded["successor_session_id"], policy)
    _validate_failed_snapshot(db, actual, recorded)
    current_children, sealed_children = actual.get("intermediate_proofs", []), recorded.get("intermediate_proofs", [])
    p._require(isinstance(sealed_children, list) and len(current_children) == len(sealed_children),
               "Failed-prefix recovery chain changed.")
    for current_child, sealed_child in zip(current_children, sealed_children):
        _validate_failed_snapshot(db, current_child, sealed_child)
    evidence = recorded["successor_evidence"]
    p._require({key: successor[key] for key in evidence["session"]} == evidence["session"],
               "Successor identity changed after prefix recovery.")
    segment = p._one(db, "SELECT * FROM packet_capture_segments WHERE id=:id", {"id": evidence["segment"]["id"]})
    features = p._rows(db, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id ORDER BY id",
                       {"id": evidence["segment"]["id"]})
    empty = p._rows(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id "
                    "AND window_start<:start ORDER BY window_start,id",
                    {"id": successor["id"], "start": evidence["segment"]["window_start"]})
    p._require(segment == evidence["segment"]
               and packet_feature_evidence_matches(features, evidence["features_sha256"])
               and len(features) == evidence["feature_count"] and empty == evidence["empty_prefix"],
               "Successor readiness evidence changed after prefix recovery.")
    p._require(not p._rows(db, "SELECT f.id FROM packet_feature_logs f JOIN packet_capture_segments s "
                          "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id AND s.window_start<:start LIMIT 1",
                          {"id": successor["id"], "start": evidence["segment"]["window_start"]}),
               "Successor EMPTY prefix gained Packet Features.")


def _confirmed_tail_audit(db, proof, expected_ids):
    """Bind later progress to the recorded pair at this exact failed prefix end."""
    p._require(p._one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='packet_detection_gaps'"),
               "Packet progress beyond the prefix requires a confirmed gap audit.")
    failure = proof["failure"]
    audit = p._one(db, "SELECT * FROM packet_detection_gaps WHERE window_start=:start AND window_end=:end",
                   {"start": proof["prefix_end"], "end": failure["window_end"]})
    evidence = validated_confirmed_gap_evidence(audit) if audit else None
    p._require(evidence is not None, "Missing or invalid confirmed gap audit for the failed tail.")
    source = proof["target_snapshot"]["session"]
    target = p._session(db, proof["successor_session_id"])
    successor = proof["successor_evidence"]
    first = successor["empty_prefix"][0] if successor["empty_prefix"] else successor["segment"]
    p._require(evidence["reason"] == "LATE_CAPTURE"
               and evidence["source"] == {key: source[key] for key in SESSION_FIELDS + ("status", "ended_at")}
               and evidence["target"] == {key: target[key] for key in SESSION_FIELDS}
               and evidence.get("source_last_segment") == failure
               and evidence.get("target_first_segment") == first,
               "Confirmed gap audit does not match the preserved failed tail and successor.")
    p._require(all("last_processed_id" in row and row["last_processed_id"] == expected_ids[row["detector_name"]]
                   for row in evidence["checkpoints_before"]),
               "Confirmed gap audit does not prove healthy prefix source consumption.")
    return audit


def _prefix_source_ids(db, proof, previous_ids):
    expected_ids = {}
    for name in p.PACKET_DETECTORS:
        direction = "AND f.direction='INBOUND' " if name == "packet_rule" else ""
        rows = p._rows(db, "SELECT MAX(f.id) AS id FROM packet_feature_logs f JOIN packet_capture_segments s "
                       "ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id " + direction,
                       {"id": proof["target_snapshot"]["session"]["id"]})
        expected_ids[name] = rows[0]["id"] if rows[0]["id"] is not None else previous_ids[name]
    return expected_ids


def _check_chain_drain(db, operation_id, plan, checkpoints):
    """Project two pair views only after get_resume_audit validated the full plan."""
    proof = plan["failed_prefix_recovery"]
    child, = proof["intermediate_proofs"]
    middle = child["target_snapshot"]["session"]
    # The first successor is the middle Session, not the final running Session
    # stored at top level. Its first row was bound by the validated prefix seal.
    first = p._one(db, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id "
                   "ORDER BY window_start,id LIMIT 1", {"id": middle["id"]})
    pairs = (
        {**proof, "successor_session_id": proof["chain_adjacency"][0]["successor_session"]["session_id"],
         "successor_evidence": {"empty_prefix": [], "segment": first}},
        {**child, "successor_evidence": proof["successor_evidence"]},
    )
    boundaries = {checkpoints[name]["last_completed_window_end"] for name in p.PACKET_DETECTORS}
    p._require(len(boundaries) == 1, "Packet checkpoints disagree during failed-prefix chain drain.")
    boundary = parse_db_utc(boundaries.pop())
    expected_ids = {name: plan["checkpoints"][name]["before"]["last_processed_id"] for name in p.PACKET_DETECTORS}
    confirmed = []
    result = {"operation_id": operation_id, "successor_session_id": proof["successor_session_id"],
              "prefix_ends": [pair["prefix_end"] for pair in pairs], "confirmed_tails": confirmed,
              "checkpoints": checkpoints}
    for pair in pairs:
        end = pair["prefix_end"]
        expected_ids = _prefix_source_ids(db, pair, expected_ids)
        result.update(prefix_end=end, failed_segment_id=pair["failure"]["id"])
        if boundary < parse_db_utc(end):
            return {**result, "result": "WAIT", "reason": "Healthy prefix processing is incomplete."}
        tail = {"source_session_id": pair["target_snapshot"]["session"]["session_id"],
                "successor_session_id": pair["successor_session_id"], "failed_segment_id": pair["failure"]["id"],
                "window_start": end, "window_end": pair["failure"]["window_end"]}
        if boundary == parse_db_utc(end):
            p._require(all(checkpoints[name]["last_processed_id"] == expected_ids[name] for name in p.PACKET_DETECTORS),
                       "Healthy prefix source IDs have not been consumed.")
            if any(parse_db_utc(row["last_completed_window_end"]) < boundary for row in checkpoints.values()):
                return {**result, "result": "WAIT", "reason": "Healthy prefix MQTT/Trust catchup is incomplete."}
            p._fully_drained(db, checkpoints, end, exact_boundaries=False)
            return {**result, "result": "PREFIX_DRAINED_RECOVERY_REQUIRED", "pending_tail": tail,
                    "reason": "This healthy prefix is drained; its failed tail has not been crossed."}
        # Validate every crossed tail before considering MQTT/Trust lag. Current
        # checkpoints alone cannot prove either prefix's historical consumption.
        gap = _confirmed_tail_audit(db, pair, expected_ids)
        p._require(boundary >= parse_db_utc(gap["window_end"])
                   and all(expected_ids[name] is None or (checkpoints[name]["last_processed_id"] is not None
                           and checkpoints[name]["last_processed_id"] >= expected_ids[name]) for name in p.PACKET_DETECTORS),
                   "Packet checkpoints do not preserve the confirmed prefix consumption.")
        confirmed.append({**tail, "status": gap["status"], "plan_sha256": gap["plan_sha256"]})
    final_end = confirmed[-1]["window_end"]
    if any(parse_db_utc(row["last_completed_window_end"]) < parse_db_utc(final_end) for row in checkpoints.values()):
        return {**result, "result": "WAIT", "reason": "Confirmed gaps MQTT/Trust catchup is incomplete."}
    p._fully_drained(db, {name: row for name, row in checkpoints.items() if name not in p.PACKET_DETECTORS},
                     final_end, exact_boundaries=False)
    return {**result, "result": "PREFIX_DRAINED_CONFIRMED_GAP"}


def check_prefix_drain(db, operation_id):
    audit = p.get_resume_audit(db, operation_id)
    plan = json.loads(audit["plan_json"])
    p._require("failed_prefix_recovery" in plan, "Operation is not an explicit failed-prefix recovery.")
    proof = plan["failed_prefix_recovery"]
    required = tuple((name, row["source_table"]) for name, row in plan["checkpoint_snapshot"].items())
    checkpoints = p._checkpoints(db, required)
    if proof.get("intermediate_proofs"):
        return _check_chain_drain(db, operation_id, plan, checkpoints)
    end = proof["prefix_end"]
    if any(parse_db_utc(row["last_completed_window_end"]) < parse_db_utc(end) for row in checkpoints.values()):
        return {"result": "WAIT", "reason": "Healthy prefix processing is incomplete.", "prefix_end": end}
    expected_ids = _prefix_source_ids(db, proof, {
        name: plan["checkpoints"][name]["before"]["last_processed_id"] for name in p.PACKET_DETECTORS})
    result = {"result": "PREFIX_DRAINED_RECOVERY_REQUIRED", "operation_id": operation_id,
            "prefix_end": end, "failed_segment_id": proof["failure"]["id"],
            "successor_session_id": proof["successor_session_id"], "checkpoints": checkpoints}
    if all(checkpoints[name]["last_completed_window_end"] == end for name in p.PACKET_DETECTORS):
        p._fully_drained(db, checkpoints, end, exact_boundaries=False)
        p._require(all(checkpoints[name]["last_processed_id"] == expected_ids[name] for name in p.PACKET_DETECTORS),
                   "Healthy prefix source IDs have not been consumed.")
        return result
    gap = _confirmed_tail_audit(db, proof, expected_ids)
    gap_end = parse_db_utc(gap["window_end"])
    p._require(all(parse_db_utc(checkpoints[name]["last_completed_window_end"]) >= gap_end
                   and (expected_ids[name] is None or (checkpoints[name]["last_processed_id"] is not None
                        and checkpoints[name]["last_processed_id"] >= expected_ids[name])) for name in p.PACKET_DETECTORS),
               "Packet checkpoints do not preserve the confirmed prefix consumption.")
    if any(parse_db_utc(row["last_completed_window_end"]) < gap_end for row in checkpoints.values()):
        return {"result": "WAIT", "reason": "Confirmed gap MQTT/Trust catchup is incomplete.", "prefix_end": end}
    # Packet consumption is proven by the exact historical pair above. The
    # unchanged shutdown helper requires Packet boundaries to be stationary;
    # use its source/Trust checks only for the remaining stages during catchup.
    p._fully_drained(db, {name: row for name, row in checkpoints.items() if name not in p.PACKET_DETECTORS},
                     gap["window_end"], exact_boundaries=False)
    return {**result, "result": "PREFIX_DRAINED_CONFIRMED_GAP", "gap_status": "UNINSPECTED",
            "gap_end": gap["window_end"], "gap_plan_sha256": gap["plan_sha256"]}
