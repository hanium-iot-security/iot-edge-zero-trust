"""Planned shutdown evidence and atomic one-time resume on the real schema."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.maintenance.planned import (
    PlannedMaintenanceError, REQUIRED_CHECKPOINTS, apply_resume, approved_intervals,
    calculate_plan_sha256, cancel_stop, finalize_stop, get_operation,
    get_processing_cutoff, inspect_resume, request_stop, resolve_planned_transition,
    get_resume_audit,
)

SOURCE = "11111111-1111-4111-8111-111111111111"
TARGET = "22222222-2222-4222-8222-222222222222"
OLD_BOOT = "33333333-3333-4333-8333-333333333333"
NEW_BOOT = "44444444-4444-4444-8444-444444444444"
BASE = datetime(2026, 10, 5, 3, 0, tzinfo=timezone.utc)


def utc(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def transaction(conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def add_session(conn, identity, start, *, status="RUNNING", gap=None):
    cursor = conn.execute("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status,"
                          "capture_gap_start,capture_gap_end) VALUES (?,'eth0',?,?,?,?,?)",
                          (identity, utc(start), utc(start), status, utc(gap) if gap is not None else None,
                           utc(start) if gap is not None else None))
    return cursor.lastrowid


def add_segment(conn, session_pk, start, status="PROCESSED"):
    row = conn.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,"
                       "status,packet_count,start_delay_seconds,captured_duration_seconds,actual_capture_started_at,"
                       "capture_stop_requested_at,capture_process_exited_at) VALUES (?,?,'eth0',?,?,?,2,0,10,?,?,?)",
                       (session_pk, f"{session_pk}-{start}.pcap", utc(start), utc(start + 10), status,
                        utc(start), utc(start + 10), utc(start + 10)))
    if status == "PROCESSED":
        conn.execute("INSERT INTO packet_feature_logs(capture_segment_id,device_id,peer_ip,direction,window_start,window_end,"
                     "packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (?,'esp32_01','192.168.0.4','INBOUND',?,?,2,100,50,50)",
                     (row.lastrowid, utc(start), utc(start + 10)))
    return row.lastrowid


def seed_planned_maintenance_database(path):
    apply_migrations(path, MIGRATIONS_DIR)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("INSERT INTO devices(device_id,ip_address,status,trust_score) VALUES ('esp32_01','192.168.0.4','isolated',20)")
    source_pk = add_session(conn, SOURCE, 0)
    add_segment(conn, source_pk, 0)
    add_segment(conn, source_pk, 10)
    conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at) VALUES ('esp32_01','iot/esp32_01','{}',2,?)", (utc(5),))
    conn.execute("INSERT INTO feature_logs(device_id,window_start,window_end,publish_count) VALUES ('esp32_01',?,?,1)", (utc(0), utc(10)))
    for detector, table in REQUIRED_CHECKPOINTS:
        last_id = 2 if table == "packet_feature_logs" else (0 if table == "detection_events" else 1)
        conn.execute("INSERT INTO detector_checkpoints VALUES (?,?,?,?,?)", (detector, table, last_id, utc(20), utc(20)))
    conn.execute("INSERT INTO firewall_rules(device_id,source_ip,status,reason) VALUES ('esp32_01','192.168.0.4','APPLIED','already isolated')")
    conn.execute("INSERT INTO isolation_history(device_id,action,trust_score) VALUES ('esp32_01','ISOLATED',20)")
    conn.commit()
    return conn, source_pk


@pytest.fixture
def db(tmp_path):
    conn, source_pk = seed_planned_maintenance_database(tmp_path / "iot.db")
    yield conn, source_pk, tmp_path
    conn.close()


def stop_request(conn):
    with transaction(conn):
        return request_stop(conn, approved_by="root/uid=0; declared=woomin", reason="Planned reboot",
                            source_session_id=SOURCE, source_boot_id=OLD_BOOT, now=utc(15))


def close_source(conn, *, status="COMPLETED"):
    conn.execute("UPDATE packet_capture_sessions SET status=?,ended_at=? WHERE session_id=?", (status, utc(20), SOURCE))
    conn.commit()


def ready(conn):
    operation = stop_request(conn)
    close_source(conn)
    with transaction(conn):
        return finalize_stop(conn, operation["operation_id"], now=utc(25))


def resume_plan(conn, operation):
    target_pk = add_session(conn, TARGET, 60, gap=20)
    add_segment(conn, target_pk, 60)
    conn.commit()
    return inspect_resume(conn, operation["operation_id"], target_session_id=TARGET, current_boot_id=NEW_BOOT,
                          time_synchronized=True, now=utc(75))


def apply(conn, plan, directory):
    with transaction(conn):
        return apply_resume(conn, plan, now=utc(80), backup_path=str((directory / "backup.db").resolve()), backup_sha256="a" * 64)


def protected(conn):
    tables = ("devices", "mqtt_logs", "feature_logs", "packet_capture_sessions", "packet_capture_segments",
              "packet_feature_logs", "detection_events", "trust_score_history", "isolation_history", "firewall_rules")
    return {table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in tables}


def test_request_is_not_ready_and_running_cutoff_follows_final_segment(db):
    conn, source_pk, _ = db
    operation = stop_request(conn)
    assert operation["status"] == "REQUESTED"
    assert operation["source_final_boundary"] is None
    assert get_processing_cutoff(conn) == BASE + timedelta(seconds=20)
    add_segment(conn, source_pk, 20, "READY")
    conn.commit()
    assert get_processing_cutoff(conn) == BASE + timedelta(seconds=30)
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="gracefully"):
        finalize_stop(conn, operation["operation_id"], now=utc(35))


def test_stop_ready_binds_whole_session_and_six_processing_stages(db):
    conn, _, _ = db
    before = protected(conn)
    operation = ready(conn)
    assert operation["status"] == "READY"
    assert operation["source_final_boundary"] == operation["maintenance_start"] == utc(20)
    assert len(json.loads(operation["checkpoint_snapshot_json"])) == 6
    assert operation["expires_at"] == utc(25 + 7 * 86400)
    assert get_processing_cutoff(conn) == BASE + timedelta(seconds=20)
    assert protected(conn)["devices"] == before["devices"]
    assert not approved_intervals(conn)


def test_atomic_resume_only_changes_pair_approval_audit_preserves_isolation(db):
    conn, _, directory = db
    operation = ready(conn)
    plan = resume_plan(conn, operation)
    before = protected(conn)
    cp_before = {row["detector_name"]: dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints")}
    audit = apply(conn, plan, directory)
    assert protected(conn) == before
    assert get_operation(conn, operation["operation_id"])["status"] == "RESUMED"
    cps = {row["detector_name"]: dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints")}
    for name, row in cps.items():
        if name in ("packet_rule", "packet_if"):
            assert row["last_completed_window_end"] == utc(60)
            assert row["last_processed_id"] == cp_before[name]["last_processed_id"] == 2
        else:
            assert row == cp_before[name]
    intervals = approved_intervals(conn)
    assert len(intervals) == 1 and intervals[0]["window_start"] == utc(20) and intervals[0]["window_end"] == utc(60)
    assert audit["source_final_boundary"] == utc(20)
    resolved = resolve_planned_transition(conn, BASE + timedelta(seconds=60), {n: cps[n] for n in ("packet_rule", "packet_if")})
    assert resolved["operation_id"] == operation["operation_id"]
    assert get_processing_cutoff(conn) is None


@pytest.mark.parametrize("stage", [name for name, _ in REQUIRED_CHECKPOINTS])
def test_unfinished_stage_cannot_authorize_shutdown(db, stage):
    conn, _, _ = db
    operation = stop_request(conn)
    close_source(conn)
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name=?", (utc(10), stage))
    conn.commit()
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="incomplete"):
        finalize_stop(conn, operation["operation_id"], now=utc(25))
    assert get_operation(conn, operation["operation_id"])["status"] == "REQUESTED"


@pytest.mark.parametrize("change", ["FAILED", "READY", "no_timing", "gap", "unconsumed", "pending_event", "null_window_event"])
def test_bad_source_or_pending_event_stays_requested(db, change):
    conn, source_pk, _ = db
    operation = stop_request(conn)
    close_source(conn)
    if change in ("FAILED", "READY"):
        conn.execute("UPDATE packet_capture_segments SET status=? WHERE id=2", (change,))
    elif change == "no_timing":
        conn.execute("UPDATE packet_capture_segments SET captured_duration_seconds=NULL WHERE id=2")
    elif change == "gap":
        conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=1")
        conn.execute("DELETE FROM packet_capture_segments WHERE id=1")
    elif change == "unconsumed":
        conn.execute("UPDATE detector_checkpoints SET last_processed_id=0 WHERE detector_name='mqtt_message_rule'")
    else:
        conn.execute("INSERT INTO detection_events(device_id,detector_type,event_type,detected_at,analysis_window_start,analysis_window_end) "
                     "VALUES ('esp32_01','RULE','TEST',?,?,?)", (utc(10), utc(0) if change == "pending_event" else None,
                                                            utc(10) if change == "pending_event" else None))
    conn.commit()
    with transaction(conn), pytest.raises(PlannedMaintenanceError):
        finalize_stop(conn, operation["operation_id"], now=utc(25))
    assert get_operation(conn, operation["operation_id"])["status"] == "REQUESTED"


def test_crash_completion_is_not_approved(db):
    conn, _, _ = db
    operation = stop_request(conn)
    close_source(conn, status="FAILED")
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="gracefully"):
        finalize_stop(conn, operation["operation_id"], now=utc(25))
    with pytest.raises(PlannedMaintenanceError, match="failed"):
        get_processing_cutoff(conn)


@pytest.mark.parametrize("gate", ["same_boot", "not_synchronized", "expired", "pair_changed", "foreign_session", "ready_feature", "gap_binding", "target_failed", "target_gap", "intervening_failed", "source_changed", "late_pending"])
def test_inspection_holds_on_unapproved_evidence(db, gate):
    conn, _, _ = db
    operation = ready(conn)
    if gate == "intervening_failed":
        add_session(conn, "55555555-5555-4555-8555-555555555555", 30, status="FAILED")
        conn.commit()
        with pytest.raises(PlannedMaintenanceError, match="intervening"):
            resume_plan(conn, operation)
        return
    plan = resume_plan(conn, operation)
    kwargs = dict(target_session_id=TARGET, current_boot_id=NEW_BOOT, time_synchronized=True, now=utc(75))
    if gate == "same_boot":
        kwargs["current_boot_id"] = OLD_BOOT
    elif gate == "not_synchronized":
        kwargs["time_synchronized"] = False
    elif gate == "expired":
        kwargs["now"] = utc(25 + 7 * 86400 + 1)
    elif gate == "pair_changed":
        conn.execute("UPDATE detector_checkpoints SET updated_at=? WHERE detector_name='packet_if'", (utc(30),))
    elif gate == "foreign_session":
        kwargs["target_session_id"] = SOURCE
    elif gate == "ready_feature":
        conn.execute("UPDATE packet_capture_segments SET status='READY' WHERE id=3")
    elif gate == "gap_binding":
        conn.execute("UPDATE packet_capture_sessions SET capture_gap_start=? WHERE session_id=?", (utc(30), TARGET))
    elif gate == "target_failed":
        conn.execute("UPDATE packet_capture_sessions SET status='FAILED' WHERE session_id=?", (TARGET,))
    elif gate == "target_gap":
        add_segment(conn, 2, 80)
    elif gate == "source_changed":
        with pytest.raises(sqlite3.IntegrityError, match="sealed"):
            conn.execute("UPDATE packet_capture_segments SET packet_count=999 WHERE id=1")
        conn.rollback()
        assert get_operation(conn, operation["operation_id"])["status"] == "READY"
        return
    else:
        conn.execute("INSERT INTO detection_events(detector_type,event_type,analysis_window_start,analysis_window_end,detected_at) "
                     "VALUES ('RULE','LATE',?,?,?)", (utc(0), utc(10), utc(70)))
    conn.commit()
    with pytest.raises((PlannedMaintenanceError, sqlite3.IntegrityError)):
        inspect_resume(conn, operation["operation_id"], **kwargs)


def test_normal_source_additions_and_target_tail_append_are_allowed(db):
    conn, _, directory = db
    operation = ready(conn)
    plan = resume_plan(conn, operation)
    conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,received_at) VALUES ('esp32_01','iot/esp32_01','{}',?)", (utc(65),))
    conn.execute("INSERT INTO feature_logs(device_id,window_start,window_end) VALUES ('esp32_01',?,?)", (utc(60), utc(70)))
    add_segment(conn, 2, 70)
    add_segment(conn, 2, 80, "READY")
    conn.execute("UPDATE detector_checkpoints SET last_processed_id=2,last_completed_window_end=?,updated_at=? "
                 "WHERE detector_name IN ('mqtt_feature_builder','mqtt_message_rule','mqtt_feature_rule')", (utc(70), utc(70)))
    conn.commit()
    assert inspect_resume(conn, operation["operation_id"], target_session_id=TARGET, current_boot_id=NEW_BOOT,
                          time_synchronized=True, now=utc(80))["plan_sha256"] == plan["plan_sha256"]
    apply(conn, plan, directory)


def test_tail_failure_added_after_plan_holds_without_mutation(db):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    add_segment(conn, 2, 70, "FAILED")
    conn.commit()
    cps = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")]
    with pytest.raises(PlannedMaintenanceError):
        apply(conn, plan, directory)
    assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")] == cps
    assert conn.execute("SELECT count(*) FROM planned_maintenance_resumes").fetchone()[0] == 0


def test_retry_after_commit_does_not_consume_or_move_twice(db):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    first = apply(conn, plan, directory)
    changes = conn.total_changes
    retry = apply(conn, plan, directory)
    assert first == retry and changes == conn.total_changes
    assert get_resume_audit(conn, plan["operation_id"])["plan_sha256"] == plan["plan_sha256"]
    assert conn.execute("SELECT count(*) FROM planned_maintenance_resumes").fetchone()[0] == 1
    other = dict(plan, reason="changed")
    other["plan_sha256"] = calculate_plan_sha256(other)
    with pytest.raises(PlannedMaintenanceError, match="another plan"):
        apply(conn, other, directory)


def test_partial_resume_failure_rolls_back_even_if_outer_caller_catches(db):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    conn.execute("CREATE TRIGGER fail_if BEFORE UPDATE ON detector_checkpoints WHEN NEW.detector_name='packet_if' "
                 "BEGIN SELECT RAISE(ABORT,'test injected failure'); END")
    conn.commit()
    before = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")]
    with transaction(conn):
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            apply_resume(conn, plan, now=utc(80), backup_path=str(directory / "backup.db"), backup_sha256="a" * 64)
    assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")] == before
    assert get_operation(conn, plan["operation_id"])["status"] == "READY"
    assert not approved_intervals(conn)


def test_audit_remains_valid_after_later_target_failure_and_checkpoint_progress(db):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    apply(conn, plan, directory)
    conn.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE session_id=?", (utc(90), TARGET))
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=?,last_processed_id=3 WHERE detector_name IN ('packet_rule','packet_if')", (utc(70),))
    conn.commit()
    assert approved_intervals(conn)[0]["window_end"] == utc(60)
    assert resolve_planned_transition(conn, BASE + timedelta(seconds=60),
                                      [dict(row) for row in conn.execute("SELECT * FROM detector_checkpoints WHERE detector_name IN ('packet_rule','packet_if')")]) is None


def test_cancel_invalidates_approval_without_mutating_capture_or_trust(db):
    conn, _, _ = db
    operation = ready(conn)
    before = protected(conn)
    with transaction(conn):
        cancelled = cancel_stop(conn, operation["operation_id"], reason="Stop orchestration failed", now=utc(30))
    assert cancelled["status"] == "CANCELLED" and protected(conn) == before
    assert get_processing_cutoff(conn) is None
    with transaction(conn), pytest.raises(PlannedMaintenanceError):
        finalize_stop(conn, operation["operation_id"], now=utc(35))


def test_source_and_approval_tampering_rejected_and_audit_immutable(db):
    conn, _, directory = db
    operation = ready(conn)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE planned_maintenance_operations SET approved_by='other' WHERE operation_id=?", (operation["operation_id"],))
    conn.rollback()
    plan = resume_plan(conn, operation)
    apply(conn, plan, directory)
    for sql in ("DELETE FROM planned_maintenance_operations", "UPDATE planned_maintenance_resumes SET backup_sha256='b'",
                "DELETE FROM planned_maintenance_resumes"):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(sql)
        conn.rollback()


def test_functions_work_on_sqlalchemy_readers_and_old_schema_absence(db):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    apply(conn, plan, directory)
    engine = create_engine(f"sqlite:///{directory / 'iot.db'}")
    with Session(engine) as session:
        assert approved_intervals(session)[0]["window_start"] == utc(20)
        assert get_processing_cutoff(session) is None
    engine.dispose()
    empty = sqlite3.connect(":memory:")
    assert approved_intervals(empty) == [] and get_processing_cutoff(empty) is None
    empty.close()


def test_required_gate_set_cannot_be_reduced_and_new_request_cannot_overlap(db):
    conn, _, _ = db
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="six"):
        request_stop(conn, approved_by="root", reason="test", source_session_id=SOURCE, source_boot_id=OLD_BOOT,
                     required_checkpoints=REQUIRED_CHECKPOINTS[:2], now=utc(15))
    stop_request(conn)
    with pytest.raises(PlannedMaintenanceError, match="active"):
        stop_request(conn)


@pytest.mark.parametrize("end,detected", [(None, None), ("invalid", utc(5)), (None, "invalid")])
def test_nullable_or_invalid_pending_event_time_holds_shutdown(db, end, detected):
    conn, _, _ = db
    operation = stop_request(conn)
    close_source(conn)
    conn.execute("INSERT INTO detection_events(detector_type,event_type,analysis_window_end,detected_at) "
                 "VALUES ('RULE','UNKNOWN',?,?)", (end, detected))
    conn.commit()
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="await Trust"):
        finalize_stop(conn, operation["operation_id"], now=utc(25))


def test_enabled_mqtt_if_checkpoint_participates_in_ready_gate(db):
    conn, _, _ = db
    conn.execute("INSERT INTO detector_checkpoints VALUES ('mqtt_if','feature_logs',1,?,?)", (utc(10), utc(10)))
    conn.commit()
    with transaction(conn):
        operation = request_stop(conn, approved_by="root", reason="test", source_session_id=SOURCE,
                                 source_boot_id=OLD_BOOT, required_checkpoints=(*REQUIRED_CHECKPOINTS, ("mqtt_if", "feature_logs")),
                                 now=utc(15))
    close_source(conn)
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="mqtt_if"):
        finalize_stop(conn, operation["operation_id"], now=utc(25))
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='mqtt_if'", (utc(20),))
    conn.commit()
    with transaction(conn):
        completed = finalize_stop(conn, operation["operation_id"], now=utc(25))
    assert len(json.loads(completed["checkpoint_snapshot_json"])) == 7


def test_runtime_interval_validation_does_not_rescan_entire_source(db, monkeypatch):
    import edge.maintenance.planned as planned
    conn, _, directory = db
    apply(conn, resume_plan(conn, ready(conn)), directory)
    monkeypatch.setattr(planned, "_source_snapshot", lambda *args: pytest.fail("runtime deep Session hash scan"))
    assert approved_intervals(conn)[0]["window_end"] == utc(60)


@pytest.mark.parametrize("processed,legacy", [(False, False), (True, False), (False, True), (True, True)])
def test_existing_gap_detection_event_holds_without_discarding_history(db, processed, legacy):
    conn, _, directory = db
    operation = ready(conn)
    plan = resume_plan(conn, operation)
    conn.execute("INSERT INTO detection_events(detector_type,event_type,analysis_window_start,analysis_window_end,detected_at,"
                 "processed_at,score_delta,applied_to_score) VALUES ('RULE','EXISTING',?,?,?,?,?,?)",
                 (None if legacy else utc(30), None if legacy else utc(40), utc(35),
                  utc(45) if processed else None, -20, int(processed)))
    conn.commit()
    before = protected(conn)
    with pytest.raises(PlannedMaintenanceError, match="overlap planned downtime"):
        apply(conn, plan, directory)
    assert protected(conn) == before
    assert get_operation(conn, operation["operation_id"])["status"] == "READY"


@pytest.mark.parametrize("received", [utc(15), "2026-10-05T03:00:19.999999Z"])
def test_late_pre_stop_source_append_cannot_be_silently_skipped(db, received):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,received_at) VALUES ('esp32_01','iot/esp32_01','{}',?)", (received,))
    conn.commit()
    with pytest.raises(PlannedMaintenanceError, match="Unconsumed pre-maintenance"):
        apply(conn, plan, directory)


def test_future_trust_boundary_cannot_be_sealed_as_ready(db):
    conn, _, _ = db
    operation = stop_request(conn)
    close_source(conn)
    conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE detector_name='trust_score_v2'", (utc(30),))
    conn.commit()
    with transaction(conn), pytest.raises(PlannedMaintenanceError, match="passed the source shutdown"):
        finalize_stop(conn, operation["operation_id"], now=utc(35))


@pytest.mark.parametrize("sql", [
    "UPDATE packet_capture_sessions SET ended_at='2026-10-05T03:00:21Z' WHERE id=1",
    "DELETE FROM packet_capture_sessions WHERE id=1",
    "INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end,status) "
    "VALUES (1,'late.pcap','eth0','2026-10-05T03:00:20Z','2026-10-05T03:00:30Z','READY')",
    "UPDATE packet_capture_segments SET packet_count=100 WHERE id=1",
    "DELETE FROM packet_capture_segments WHERE id=1",
    "INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) "
    "VALUES (1,'192.168.0.9','INBOUND','2026-10-05T03:00:00Z','2026-10-05T03:00:10Z',1,10,10,10)",
    "UPDATE packet_feature_logs SET packet_count=100 WHERE id=1",
    "DELETE FROM packet_feature_logs WHERE id=1",
])
def test_ready_seals_only_source_capture_and_features(db, sql):
    conn, _, _ = db
    ready(conn)
    before = protected(conn)
    with pytest.raises(sqlite3.IntegrityError, match="sealed"):
        conn.execute(sql)
    conn.rollback()
    assert protected(conn) == before


def test_seal_and_approval_creation_roll_back_together(db):
    conn, _, _ = db
    operation = stop_request(conn)
    close_source(conn)
    conn.execute("BEGIN IMMEDIATE")
    finalize_stop(conn, operation["operation_id"], now=utc(25))
    with pytest.raises(sqlite3.IntegrityError, match="sealed"):
        conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE id=1")
    conn.rollback()
    assert get_operation(conn, operation["operation_id"])["status"] == "REQUESTED"
    conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE id=1")
    conn.commit()


def test_ready_cancellation_preserves_existing_source_seal(db):
    conn, _, _ = db
    operation = ready(conn)
    with transaction(conn):
        cancel_stop(conn, operation["operation_id"], reason="cancel", now=utc(30))
    with pytest.raises(sqlite3.IntegrityError, match="sealed"):
        conn.execute("DELETE FROM packet_feature_logs WHERE id=1")
    conn.rollback()


def test_locked_apply_does_not_rescan_or_hash_whole_stopped_session(db, monkeypatch):
    import edge.maintenance.planned as planned
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    monkeypatch.setattr(planned, "_source_snapshot", lambda *args: pytest.fail("locked apply deep scan"))
    audit = apply(conn, plan, directory)
    assert audit["maintenance_end"] == utc(60)


@pytest.mark.parametrize("replacement", [False, True])
def test_missing_or_replaced_seal_trigger_holds_before_checkpoint_changes(db, replacement):
    conn, _, directory = db
    plan = resume_plan(conn, ready(conn))
    cps = [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")]
    conn.execute("DROP TRIGGER trg_planned_maintenance_source_feature_update")
    if replacement:
        conn.execute("CREATE TRIGGER trg_planned_maintenance_source_feature_update BEFORE UPDATE ON packet_feature_logs "
                     "BEGIN SELECT 1; END")
    conn.commit()
    with pytest.raises(PlannedMaintenanceError, match="schema/seal contract"):
        apply(conn, plan, directory)
    assert [tuple(row) for row in conn.execute("SELECT * FROM detector_checkpoints")] == cps
    assert conn.execute("SELECT count(*) FROM planned_maintenance_resumes").fetchone()[0] == 0
