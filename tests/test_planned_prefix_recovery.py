"""Explicit failed-target prefix recovery preserves real input before a new loss.

All databases are temporary SQLite copies on the real migration schema. No
service, serial port, external firewall worker, or live device is accessed.
"""
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from edge.maintenance import planned
from edge.maintenance.processing import dataset_maintenance_windows, overlaps_maintenance
from edge.packet.confirmed_gaps import advance_confirmed_packet_gap
from tests.test_planned_maintenance import (
    NEW_BOOT, OLD_BOOT, SOURCE, TARGET, add_segment, add_session, close_source,
    db as maintenance_db, protected, ready, transaction, utc,
)
from tests.test_planned_maintenance_processing import (
    BASE as PIPELINE_BASE, prepared as pipeline_db, insert, messages, packet,
    utc as pipeline_utc, real_packet_if_with_normal_predictions,
)

SUCCESSOR = "55555555-5555-4555-8555-555555555555"
THIRD = "66666666-6666-4666-8666-666666666666"


def late_tail(conn, session_pk, start, format_time=utc):
    return conn.execute(
        "INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,"
        "status,packet_count,error_code,error_message,start_delay_seconds,captured_duration_seconds) "
        "VALUES (?,NULL,'eth0',?,?,'FAILED',NULL,'LATE_CAPTURE','uncaptured late start',1.166,0)",
        (session_pk, format_time(start), format_time(start + 10)),
    ).lastrowid


@pytest.fixture
def prefix_db(maintenance_db):
    conn, _, directory = maintenance_db
    operation = ready(conn)
    target_pk = add_session(conn, TARGET, 60, status="FAILED", gap=20)
    empty = add_segment(conn, target_pk, 60, "EMPTY")
    conn.execute("UPDATE packet_capture_segments SET packet_count=16 WHERE id=?", (empty,))
    normal = [add_segment(conn, target_pk, start) for start in (70, 80)]
    failed = late_tail(conn, target_pk, 90)
    conn.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE id=?", (utc(91), target_pk))
    successor_pk = add_session(conn, SUCCESSOR, 100)
    successor_segment = add_segment(conn, successor_pk, 100)
    conn.commit()
    return conn, directory, operation, {"target": target_pk, "empty": empty, "normal": normal,
                                         "failed": failed, "successor": successor_pk,
                                         "successor_segment": successor_segment}


def inspect(conn, operation, **changes):
    options = dict(target_session_id=TARGET, successor_session_id=SUCCESSOR,
                   approved_by="root/uid=0; declared=woomin", reason="Preserve failed-target normal prefix",
                   current_boot_id=NEW_BOOT, time_synchronized=True, now=utc(120))
    options.update(changes)
    return planned.inspect_prefix_recovery(conn, operation["operation_id"], **options)


def apply(conn, plan, directory):
    with transaction(conn):
        return planned.apply_prefix_recovery(conn, plan, now=utc(125),
                                             backup_path=str((directory / "prefix.backup.db").resolve()),
                                             backup_sha256="a" * 64)


def checkpoint_rows(conn):
    return [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name")]


def test_explicit_prefix_recovery_changes_four_rows_keeps_originals_and_first_boundary(prefix_db):
    conn, directory, operation, ids = prefix_db
    before = protected(conn)
    cps = {row["detector_name"]: dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints")}
    plan = inspect(conn, operation)
    mode = plan["failed_prefix_recovery"]
    assert mode["approved_by"] == "root/uid=0; declared=woomin"
    assert mode["reason"] == "Preserve failed-target normal prefix"
    assert mode["prefix_end"] == utc(90)
    assert mode["successor_session_id"] == SUCCESSOR
    assert mode["target_snapshot"]["session"]["status"] == "FAILED"
    assert mode["failure"] == dict(conn.execute("SELECT * FROM packet_capture_segments WHERE id=?", (ids["failed"],)).fetchone())
    assert plan["maintenance_end"] == utc(60)
    assert plan["first_target_evidence"]["segment"]["window_start"] == utc(70)
    assert plan["first_target_evidence"]["empty_prefix"][0]["packet_count"] == 16
    changes = conn.total_changes
    audit = apply(conn, plan, directory)
    assert conn.total_changes - changes == 4
    assert protected(conn) == before
    for row in conn.execute("SELECT * FROM detector_checkpoints"):
        old = cps[row["detector_name"]]
        assert row["last_processed_id"] == old["last_processed_id"]
        assert row["last_completed_window_end"] == (utc(60) if row["detector_name"] in planned.PACKET_DETECTORS else old["last_completed_window_end"])
    assert audit["maintenance_end"] == utc(60)
    assert planned.get_processing_cutoff(conn) is None
    assert planned.approved_intervals(conn)[0]["window_end"] == utc(60)
    assert planned.get_resume_audit(conn, operation["operation_id"])["plan_sha256"] == plan["plan_sha256"]
    changes = conn.total_changes
    assert apply(conn, plan, directory) == audit
    assert conn.total_changes == changes
    assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 1


def test_regular_automatic_resume_and_apply_cannot_consume_manual_prefix_mode(prefix_db):
    conn, directory, operation, _ = prefix_db
    with pytest.raises(planned.PlannedMaintenanceError):
        planned.inspect_resume(conn, operation["operation_id"], target_session_id=TARGET,
                               current_boot_id=NEW_BOOT, time_synchronized=True, now=utc(120))
    plan = inspect(conn, operation)
    before, cps = protected(conn), checkpoint_rows(conn)
    with transaction(conn), pytest.raises(planned.PlannedMaintenanceError):
        planned.apply_resume(conn, plan, now=utc(125), backup_path=str((directory / "backup.db").resolve()),
                             backup_sha256="a" * 64)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


@pytest.mark.parametrize("options", [
    {"approved_by": ""}, {"approved_by": "   "}, {"reason": ""}, {"reason": "   "},
    {"current_boot_id": OLD_BOOT}, {"time_synchronized": False},
    {"now": utc(20)}, {"now": utc(25 + 8 * 86400)}, {"now": "2026-10-05 03:02:00"},
])
def test_fresh_approval_time_and_boot_gates_hold_without_mutation(prefix_db, options):
    conn, _, operation, _ = prefix_db
    before, cps = protected(conn), checkpoint_rows(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        inspect(conn, operation, **options)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


@pytest.mark.parametrize("change", [
    "pcap", "captured_start", "stop", "exited", "duration", "packet_count", "failed_features",
    "failure_wrong_error", "another_failure", "prefix_ready", "prefix_late", "missing_prefix",
    "target_running", "target_ended_before_failure", "target_ended_after_failure", "gap_changed",
    "successor_completed", "successor_interface", "successor_ready", "another_running", "packet_checkpoint_changed",
    "failure_interface", "failure_message_missing", "failure_message_blank", "failure_message_whitespace",
    "failure_delay_at_limit", "failure_delay_nonfinite",
])
def test_nonexact_loss_prefix_successor_or_checkpoint_keeps_approval_unconsumed(prefix_db, change):
    conn, _, operation, ids = prefix_db
    field = {"pcap": ("file_name", "failed.pcap"), "captured_start": ("actual_capture_started_at", utc(90)),
             "stop": ("capture_stop_requested_at", utc(100)), "exited": ("capture_process_exited_at", utc(100)),
             "duration": ("captured_duration_seconds", 0.1), "packet_count": ("packet_count", 1),
             "failure_wrong_error": ("error_code", "PARTIAL_CAPTURE"), "failure_interface": ("capture_interface", "wlan0"),
             "failure_message_missing": ("error_message", None), "failure_message_blank": ("error_message", ""),
             "failure_message_whitespace": ("error_message", "   "),
             "failure_delay_at_limit": ("start_delay_seconds", 1.01), "failure_delay_nonfinite": ("start_delay_seconds", float("inf"))}
    if change in field:
        name, value = field[change]
        # Also reject an externally corrupted copy independently of its CHECK.
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(f"UPDATE packet_capture_segments SET {name}=? WHERE id=?", (value, ids["failed"]))
        conn.execute("PRAGMA ignore_check_constraints=OFF")
    elif change == "failed_features":
        conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,"
                     "packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (?,'192.168.0.4','INBOUND',?,?,1,10,10,10)",
                     (ids["failed"], utc(90), utc(100)))
    elif change in ("another_failure", "prefix_ready"):
        segment = ids["normal"][0]
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (segment,))
        conn.execute("UPDATE packet_capture_segments SET status=?,error_code=? WHERE id=?",
                     ("FAILED" if change == "another_failure" else "READY",
                      "PARTIAL_CAPTURE" if change == "another_failure" else None, segment))
    elif change == "prefix_late":
        conn.execute("UPDATE packet_capture_segments SET start_delay_seconds=1.02 WHERE id=?", (ids["empty"],))
    elif change == "missing_prefix":
        conn.execute("DELETE FROM packet_capture_segments WHERE id=?", (ids["empty"],))
    elif change == "target_running":
        conn.execute("UPDATE packet_capture_sessions SET status='RUNNING' WHERE id=?", (ids["target"],))
    elif change.startswith("target_ended"):
        conn.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE id=?",
                     (utc(89 if change.endswith("before_failure") else 101), ids["target"]))
    elif change == "gap_changed":
        conn.execute("UPDATE packet_capture_sessions SET capture_gap_start=? WHERE id=?", (utc(30), ids["target"]))
    elif change == "successor_completed":
        conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE id=?", (utc(110), ids["successor"]))
    elif change == "successor_interface":
        conn.execute("UPDATE packet_capture_sessions SET capture_interface='wlan0' WHERE id=?", (ids["successor"],))
    elif change == "successor_ready":
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (ids["successor_segment"],))
        conn.execute("UPDATE packet_capture_segments SET status='READY' WHERE id=?", (ids["successor_segment"],))
    elif change == "another_running":
        add_session(conn, THIRD, 120)
    else:
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_rule'", (utc(30),))
    conn.commit()
    before, cps = protected(conn), checkpoint_rows(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        inspect(conn, operation)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


def test_intervening_normal_session_cannot_be_skipped_for_later_running_successor(prefix_db):
    conn, _, operation, ids = prefix_db
    conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (ids["successor_segment"],))
    conn.execute("DELETE FROM packet_capture_segments WHERE id=?", (ids["successor_segment"],))
    conn.execute("UPDATE packet_capture_sessions SET session_id=?,status='COMPLETED',ended_at=? WHERE id=?",
                 (THIRD, utc(110), ids["successor"]))
    add_segment(conn, ids["successor"], 100)
    later = add_session(conn, SUCCESSOR, 110)
    add_segment(conn, later, 110)
    conn.commit()
    before, cps = protected(conn), checkpoint_rows(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        inspect(conn, operation)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


def test_source_seal_cannot_be_removed_to_accept_changed_source(prefix_db):
    conn, _, operation, _ = prefix_db
    seal_sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='trg_planned_maintenance_source_segment_update'").fetchone()[0]
    conn.execute("DROP TRIGGER trg_planned_maintenance_source_segment_update")
    conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE capture_session_id=1 AND window_start=?", (utc(0),))
    conn.execute(seal_sql)  # The exact schema is restored; the source hash still differs.
    conn.commit()
    before, cps = protected(conn), checkpoint_rows(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        inspect(conn, operation)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"


@pytest.mark.parametrize("change", ["prefix", "failure", "successor_first"])
@pytest.mark.parametrize("committed", [False, True])
def test_evidence_changes_before_apply_or_after_commit_are_detected(prefix_db, change, committed):
    conn, directory, operation, ids = prefix_db
    plan = inspect(conn, operation)
    if committed:
        apply(conn, plan, directory)
    target_id = {"prefix": ids["empty"], "failure": ids["failed"], "successor_first": ids["successor_segment"]}[change]
    conn.execute("UPDATE packet_capture_segments SET error_message='changed evidence' WHERE id=?", (target_id,))
    conn.commit()
    before, cps = protected(conn), checkpoint_rows(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        if committed:
            planned.get_resume_audit(conn, operation["operation_id"])
        else:
            apply(conn, plan, directory)
    assert protected(conn) == before and checkpoint_rows(conn) == cps
    if committed:
        with pytest.raises(planned.PlannedMaintenanceError):
            planned.approved_intervals(conn)
    else:
        assert planned.get_operation(conn, operation["operation_id"])["status"] == "READY"
        assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 0


def advance_for_drain(conn, end=90):
    for name, source in planned.REQUIRED_CHECKPOINTS:
        if source == "packet_feature_logs":
            direction = " AND direction='INBOUND'" if name == "packet_rule" else ""
            last_id = conn.execute("SELECT MAX(id) FROM packet_feature_logs WHERE window_end<=?" + direction, (utc(end),)).fetchone()[0]
        else:
            last_id = conn.execute("SELECT last_processed_id FROM detector_checkpoints WHERE detector_name=?", (name,)).fetchone()[0]
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=?,last_processed_id=? "
                     "WHERE detector_name=?", (utc(end), utc(end), last_id, name))
    conn.commit()


def test_drain_requires_real_consumption_and_does_not_skip_failed_tail(prefix_db):
    conn, directory, operation, _ = prefix_db
    apply(conn, inspect(conn, operation), directory)
    before = checkpoint_rows(conn)
    assert planned.check_prefix_drain(conn, operation["operation_id"])["result"] == "WAIT"
    assert checkpoint_rows(conn) == before
    advance_for_drain(conn)
    before = protected(conn), checkpoint_rows(conn), conn.total_changes
    result = planned.check_prefix_drain(conn, operation["operation_id"])
    assert result["result"] == "PREFIX_DRAINED_RECOVERY_REQUIRED"
    assert (protected(conn), checkpoint_rows(conn), conn.total_changes) == before
    assert all(row["last_completed_window_end"] == utc(90) for row in conn.execute("SELECT * FROM detector_checkpoints"))


@pytest.mark.parametrize("confirmed_gap", [False, True])
def test_rule_drain_uses_inbound_maximum_and_if_uses_all_directions(prefix_db, confirmed_gap):
    conn, directory, operation, ids = prefix_db
    conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,device_id,peer_ip,direction,window_start,window_end,"
                 "packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (?,'esp32_01','192.168.0.4','OUTBOUND',?,?,1,10,10,10)",
                 (ids["normal"][-1], utc(80), utc(90)))
    conn.commit()
    apply(conn, inspect(conn, operation), directory)
    advance_for_drain(conn)
    rule = conn.execute("SELECT last_processed_id FROM detector_checkpoints WHERE detector_name='packet_rule'").fetchone()[0]
    ai = conn.execute("SELECT last_processed_id FROM detector_checkpoints WHERE detector_name='packet_if'").fetchone()[0]
    assert rule < ai
    if confirmed_gap:
        record_confirmed_tail(conn)
        advance_for_drain(conn, 100)
    assert planned.check_prefix_drain(conn, operation["operation_id"])["result"] == (
        "PREFIX_DRAINED_CONFIRMED_GAP" if confirmed_gap else "PREFIX_DRAINED_RECOVERY_REQUIRED")


def record_confirmed_tail(conn):
    """Use the actual gap transition after the fixture simulates prefix processing."""
    path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    try:
        with Session(engine) as db:
            result = advance_confirmed_packet_gap(db, range_start=planned.parse_db_utc(utc(90)),
                                                  cutoff=planned.parse_db_utc(utc(110)))
            assert result is not None
            db.commit()
    finally:
        engine.dispose()


def test_confirmed_tail_waits_for_mqtt_trust_and_accepts_later_real_progress(prefix_db):
    conn, directory, operation, _ = prefix_db
    apply(conn, inspect(conn, operation), directory)
    advance_for_drain(conn)
    originals = protected(conn)
    record_confirmed_tail(conn)
    assert planned.check_prefix_drain(conn, operation["operation_id"])["result"] == "WAIT"
    advance_for_drain(conn, 100)  # The gap is caught up; source IDs are still the prefix IDs.
    for end in (100, 110):
        advance_for_drain(conn, end)
        before = checkpoint_rows(conn), conn.total_changes
        result = planned.check_prefix_drain(conn, operation["operation_id"])
        assert result["result"] == "PREFIX_DRAINED_CONFIRMED_GAP"
        assert result["gap_status"] == "UNINSPECTED" and result["gap_end"] == utc(100)
        assert (checkpoint_rows(conn), conn.total_changes) == before
    assert protected(conn) == originals


@pytest.mark.parametrize("change", [
    "no_audit", "bad_digest", "invalid_json", "wrong_source", "wrong_target", "wrong_window",
    "wrong_reason", "wrong_failure", "wrong_first_segment", "wrong_boundary", "missing_pair",
    "wrong_rule_id", "wrong_if_id", "packet_boundary_split", "current_id_regressed",
])
def test_later_prefix_progress_needs_exact_unmodified_gap_consumption_evidence(prefix_db, change):
    conn, directory, operation, _ = prefix_db
    apply(conn, inspect(conn, operation), directory)
    advance_for_drain(conn)
    if change != "no_audit":
        record_confirmed_tail(conn)
    advance_for_drain(conn, 110)
    if change == "packet_boundary_split":
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='packet_if'", (utc(90),))
    elif change == "current_id_regressed":
        conn.execute("UPDATE detector_checkpoints SET last_processed_id=3 WHERE detector_name='packet_if'")
    elif change != "no_audit":
        audit = dict(conn.execute("SELECT * FROM packet_detection_gaps").fetchone())
        evidence = json.loads(audit["evidence_json"])
        if change in ("wrong_source", "wrong_target"):
            key = "source" if change == "wrong_source" else "target"
            evidence[key]["session_id"] = SOURCE
            audit[key + "_session_id"] = SOURCE
        elif change == "wrong_window":
            audit["window_end"] = evidence["window_end"] = utc(110)
        elif change == "wrong_reason":
            audit["reason"] = evidence["reason"] = "RECORDED_CAPTURE_GAP"
        elif change == "wrong_failure":
            evidence["source_last_segment"]["id"] += 1
        elif change == "wrong_first_segment":
            evidence["target_first_segment"]["id"] += 1
        elif change == "wrong_boundary":
            evidence["checkpoints_before"][0]["last_completed_window_end"] = utc(80)
        elif change == "missing_pair":
            evidence["checkpoints_before"].pop()
        elif change in ("wrong_rule_id", "wrong_if_id"):
            name = "packet_rule" if change == "wrong_rule_id" else "packet_if"
            next(row for row in evidence["checkpoints_before"] if row["detector_name"] == name)["last_processed_id"] = 3
        audit["evidence_json"] = "{" if change == "invalid_json" else json.dumps(evidence)
        audit["plan_sha256"] = "0" * 64 if change == "bad_digest" else planned._digest(evidence)
        trigger = conn.execute("SELECT sql FROM sqlite_master WHERE name='packet_detection_gaps_no_update'").fetchone()[0]
        conn.execute("DROP TRIGGER packet_detection_gaps_no_update")
        conn.execute("UPDATE packet_detection_gaps SET source_session_id=:source_session_id,target_session_id=:target_session_id,"
                     "window_end=:window_end,reason=:reason,evidence_json=:evidence_json,plan_sha256=:plan_sha256", audit)
        conn.execute(trigger)
    conn.commit()
    before = protected(conn), checkpoint_rows(conn), conn.total_changes
    with pytest.raises(planned.PlannedMaintenanceError):
        planned.check_prefix_drain(conn, operation["operation_id"])
    assert (protected(conn), checkpoint_rows(conn), conn.total_changes) == before


@pytest.mark.parametrize("confirmed_gap", [False, True])
def test_new_unconsumed_pre_prefix_message_or_pending_event_holds_drain(prefix_db, confirmed_gap):
    conn, directory, operation, _ = prefix_db
    apply(conn, inspect(conn, operation), directory)
    advance_for_drain(conn)
    if confirmed_gap:
        record_confirmed_tail(conn)
        advance_for_drain(conn, 110)
    boundary = 100 if confirmed_gap else 90
    conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at) "
                 "VALUES ('esp32_01','iot/esp32_01/sensor','{}',2,?)", (utc(boundary - 5),))
    conn.commit()
    with pytest.raises(planned.PlannedMaintenanceError):
        planned.check_prefix_drain(conn, operation["operation_id"])
    last_id = conn.execute("SELECT MAX(id) FROM mqtt_logs").fetchone()[0]
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=? WHERE source_table='mqtt_logs'", (last_id,))
    conn.execute("INSERT INTO detection_events(detector_type,event_type,analysis_window_start,analysis_window_end,detected_at) "
                 "VALUES ('RULE','PENDING',?,?,?)", (utc(boundary - 10), utc(boundary), utc(boundary)))
    conn.commit()
    with pytest.raises(planned.PlannedMaintenanceError):
        planned.check_prefix_drain(conn, operation["operation_id"])


def test_enabled_mqtt_if_is_required_to_drain_supported_seven_stage_profile(maintenance_db):
    conn, _, directory = maintenance_db
    conn.execute("INSERT INTO detector_checkpoints VALUES ('mqtt_if','feature_logs',1,?,?)", (utc(20), utc(20)))
    conn.commit()
    with transaction(conn):
        requested = planned.request_stop(
            conn, approved_by="woomin", reason="planned reboot with active MQTT IF", source_session_id=SOURCE,
            source_boot_id=OLD_BOOT, required_checkpoints=(*planned.REQUIRED_CHECKPOINTS, ("mqtt_if", "feature_logs")),
            now=utc(15),
        )
    close_source(conn)
    with transaction(conn):
        operation = planned.finalize_stop(conn, requested["operation_id"], now=utc(25))
    target = add_session(conn, TARGET, 60, status="FAILED", gap=20)
    empty = add_segment(conn, target, 60, "EMPTY")
    conn.execute("UPDATE packet_capture_segments SET packet_count=16 WHERE id=?", (empty,))
    for start in (70, 80):
        add_segment(conn, target, start)
    late_tail(conn, target, 90)
    conn.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE id=?", (utc(91), target))
    successor = add_session(conn, SUCCESSOR, 100)
    add_segment(conn, successor, 100)
    conn.commit()
    plan = inspect(conn, operation)
    assert set(plan["checkpoint_snapshot"]) == {name for name, _ in planned.REQUIRED_CHECKPOINTS} | {"mqtt_if"}
    apply(conn, plan, directory)
    advance_for_drain(conn)  # Six stages finish; active MQTT IF has not run yet.
    before = checkpoint_rows(conn), conn.total_changes
    assert planned.check_prefix_drain(conn, operation["operation_id"])["result"] == "WAIT"
    assert (checkpoint_rows(conn), conn.total_changes) == before
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,updated_at=? WHERE detector_name='mqtt_if'",
                 (utc(90), utc(90)))
    conn.commit()
    result = planned.check_prefix_drain(conn, operation["operation_id"])
    assert result["result"] == "PREFIX_DRAINED_RECOVERY_REQUIRED"
    assert result["checkpoints"]["mqtt_if"]["last_completed_window_end"] == utc(90)


@pytest.mark.parametrize("confirmed_gap", [False, True])
def test_real_pipeline_processes_empty_and_normal_prefix_then_waits_at_new_loss(pipeline_db, monkeypatch, confirmed_gap):
    from edge.detection.packet_rule_detector import PacketRuleDetectorStage
    from edge.detection.mqtt_adapters import MqttFeatureRuleStage, MqttMessageRuleStage
    from edge.features.collect_feature_logs import produce_mqtt_features_until
    from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
    from edge.orchestration.run_detection_orchestrator import run_orchestration_cycle, CYCLE_COMPLETED
    from edge.orchestration.stage_registry import StageRegistry, ConfiguredStage
    from edge.packet.capture_policy import CapturePolicy
    from edge.orchestration import run_detection_orchestrator as orchestration

    monkeypatch.setattr(orchestration, "settings", orchestration.settings.model_copy(
        update={"packet_confirmed_gap_policy_enabled": confirmed_gap}))

    path, factory, operation = pipeline_db
    target, successor, boot = str(uuid4()), str(uuid4()), str(uuid4())
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        target_pk = insert(conn, "packet_capture_sessions", session_id=target, capture_interface="eth0",
                           started_at=pipeline_utc(25), first_window_start=pipeline_utc(30), status="FAILED",
                           ended_at=pipeline_utc(61), capture_gap_start=pipeline_utc(10), capture_gap_end=pipeline_utc(30))
        empty = insert(conn, "packet_capture_segments", capture_session_id=target_pk, file_name="empty.pcap",
                       capture_interface="eth0", window_start=pipeline_utc(30), window_end=pipeline_utc(40),
                       status="EMPTY", packet_count=16, start_delay_seconds=0, captured_duration_seconds=10)
        packet(conn, target_pk, 40)
        last_feature = packet(conn, target_pk, 50)
        failed = late_tail(conn, target_pk, 60, pipeline_utc)
        successor_pk = insert(conn, "packet_capture_sessions", session_id=successor, capture_interface="eth0",
                              started_at=pipeline_utc(61), first_window_start=pipeline_utc(70), status="RUNNING")
        successor_feature = packet(conn, successor_pk, 70)
        for start in (10, 20):
            messages(conn, start, malformed=True)
        for start in (30, 40, 50, 60, 70):
            messages(conn, start)
        conn.commit()
        originals = {table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                     for table in ("devices", "device_policy_revisions", "mqtt_logs", "packet_capture_sessions", "packet_capture_segments", "packet_feature_logs")}
        plan = planned.inspect_prefix_recovery(conn, operation, target_session_id=target, successor_session_id=successor,
                                               approved_by="woomin", reason="Preserve real prefix before uncaptured loss",
                                               current_boot_id=boot, time_synchronized=True, now=pipeline_utc(85))
        conn.execute("BEGIN IMMEDIATE")
        planned.apply_prefix_recovery(conn, plan, now=pipeline_utc(85),
                                      backup_path=str(path.with_suffix(".backup.db")), backup_sha256="a" * 64)
        conn.commit()
    with factory.begin() as db:
        produced = produce_mqtt_features_until(db, producer_cutoff=PIPELINE_BASE + timedelta(seconds=80))
        assert produced.created_feature_count == 5
        assert dataset_maintenance_windows(db) == ((PIPELINE_BASE + timedelta(seconds=10), PIPELINE_BASE + timedelta(seconds=30)),)
        assert not overlaps_maintenance(dataset_maintenance_windows(db), PIPELINE_BASE + timedelta(seconds=30), PIPELINE_BASE + timedelta(seconds=40))
    ai, predicted = real_packet_if_with_normal_predictions()
    stages = (MqttFeatureRuleStage(), MqttMessageRuleStage(),
              PacketFeatureReadyStage(PacketRuleDetectorStage(capture_policy=CapturePolicy())), PacketFeatureReadyStage(ai))
    registry = StageRegistry(tuple(ConfiguredStage(stage.detector_name, stage, True) for stage in stages))
    assert run_orchestration_cycle(session_factory=factory, registry=registry).status == CYCLE_COMPLETED
    processing = run_orchestration_cycle(session_factory=factory, registry=registry)
    assert processing.status == CYCLE_COMPLETED and processing.cutoff == PIPELINE_BASE + timedelta(seconds=60)
    assert len(predicted) == 2 and all(row["packet_count"] == 2 for row in predicted)
    waiting = run_orchestration_cycle(session_factory=factory, registry=registry)
    if confirmed_gap:
        assert waiting.status == CYCLE_COMPLETED and waiting.cutoff == PIPELINE_BASE + timedelta(seconds=70)
        continued = run_orchestration_cycle(session_factory=factory, registry=registry)
        assert continued.status == CYCLE_COMPLETED and continued.cutoff == PIPELINE_BASE + timedelta(seconds=80)
        assert len(predicted) == 3
    else:
        assert waiting.status != CYCLE_COMPLETED
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        for name in planned.PACKET_DETECTORS:
            cp = conn.execute("SELECT * FROM detector_checkpoints WHERE detector_name=?", (name,)).fetchone()
            assert cp["last_completed_window_end"] == pipeline_utc(80 if confirmed_gap else 60)
            assert cp["last_processed_id"] == (successor_feature if confirmed_gap else last_feature)
        before_check = conn.total_changes
        result = planned.check_prefix_drain(conn, operation)
        assert result["result"] == ("PREFIX_DRAINED_CONFIRMED_GAP" if confirmed_gap else "PREFIX_DRAINED_RECOVERY_REQUIRED")
        assert conn.total_changes == before_check
        if confirmed_gap:
            assert result["gap_status"] == "UNINSPECTED"
        assert conn.execute("SELECT status,error_code FROM packet_capture_segments WHERE id=?", (failed,)).fetchone()[:] == ("FAILED", "LATE_CAPTURE")
        assert conn.execute("SELECT packet_count FROM packet_capture_segments WHERE id=?", (empty,)).fetchone()[0] == 16
        for table, rows in originals.items():
            assert [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")] == rows
        assert conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0] == 0
