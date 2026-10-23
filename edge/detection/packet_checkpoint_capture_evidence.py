"""Freeze recovery inputs while permitting only new READY Capture rows.

Call in an explicit SQLite snapshot, then compare the same boundary in the
verified backup and under BEGIN IMMEDIATE. MQTT writes are outside this evidence.
"""
from datetime import timedelta
import hashlib
import json

from edge.detection.phase4_time import parse_db_utc, require_utc_window_boundary
from edge.packet.capture_policy import CaptureEligibilitySegment, CapturePolicy, is_capture_eligible


def _digest(rows):
    digest = hashlib.sha256()
    for row in rows:
        digest.update(json.dumps(dict(row), sort_keys=True, separators=(",", ":")).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def capture_evidence(db, plan, *, baseline=None):
    # Import here to avoid a cycle with the canonical recovery executor.
    from edge.detection.packet_checkpoint_recovery import PacketCheckpointRecoveryError as Error

    if not db.in_transaction:
        raise Error("capture evidence requires a database snapshot")
    sessions = db.execute("SELECT * FROM packet_capture_sessions ORDER BY id").fetchall()
    running = [row for row in sessions if row["status"] == "RUNNING"]
    if len(running) != 1:
        raise Error("capture evidence requires one RUNNING session")
    running = running[0]
    approved_running = (plan["target_session_id"] if plan["mode"] == "live-resume"
                        else (plan["bounded_replay"].get("later_running_session") or {}).get("session_id"))
    if running["session_id"] != approved_running:
        raise Error("approved RUNNING Capture changed")
    protected = {plan["current_session_id"], plan["target_session_id"], running["session_id"]}
    protected.update(row["session_id"] for row in plan["sessions_between"])
    ids = sorted(row["id"] for row in sessions if row["session_id"] in protected)
    placeholders = ",".join("?" for _ in ids)
    segments = db.execute("SELECT * FROM packet_capture_segments WHERE capture_session_id=? ORDER BY window_start,id",
                          (running["id"],)).fetchall()
    boundary = baseline["capture_segment_id"] if baseline is not None else max((row["id"] for row in segments), default=0)
    next_start = require_utc_window_boundary(parse_db_utc(running["first_window_start"]), "capture first window")
    policy = CapturePolicy.from_env()
    for row in segments:
        start = parse_db_utc(row["window_start"])
        end = parse_db_utc(row["window_end"])
        if start != next_start or end != start + timedelta(seconds=10) or row["error_code"] is not None:
            raise Error("Capture is failed or discontinuous")
        next_start = end
        if row["status"] not in ("PROCESSED", "EMPTY", "READY"):
            raise Error("Capture is failed or discontinuous")
        if row["id"] > boundary:
            # Use the shared timing predicate; the actual row remains READY.
            timing = CaptureEligibilitySegment("PROCESSED", row["error_code"],
                                                row["start_delay_seconds"], row["captured_duration_seconds"])
            if (row["status"] != "READY" or row["capture_interface"] != running["capture_interface"]
                    or not row["file_name"] or row["packet_count"] is not None or row["processed_at"] is not None
                    or not is_capture_eligible(timing, policy).eligible):
                raise Error("only normal READY Capture appends are permitted")
    return {
        "capture_segment_id": boundary,
        "sessions": _digest(sessions),
        "schema": _digest(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")),
        "migrations": _digest(db.execute("SELECT * FROM schema_migrations ORDER BY version")),
        "segments": _digest(db.execute(
            f"SELECT * FROM packet_capture_segments WHERE capture_session_id IN ({placeholders}) "
            "AND (capture_session_id<>? OR id<=?) ORDER BY id", (*ids, running["id"], boundary))),
        # No Packet feature writes are allowed while the extractor locks are held.
        "features": _digest(db.execute(
            f"SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s ON s.id=f.capture_segment_id "
            f"WHERE s.capture_session_id IN ({placeholders}) ORDER BY f.id", ids)),
        "packet_checkpoints": _digest(db.execute(
            "SELECT * FROM detector_checkpoints WHERE detector_name IN ('packet_rule','packet_if') ORDER BY detector_name,source_table")),
        "audits": _digest(db.execute("SELECT * FROM packet_checkpoint_recoveries ORDER BY id")),
    }
