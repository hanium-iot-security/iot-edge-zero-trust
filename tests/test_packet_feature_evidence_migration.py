"""Real Migration 012 -> 013 keeps old seals and rejects changed bound evidence."""
from copy import deepcopy
from datetime import timedelta
import json
import shutil
import sqlite3
import struct

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.maintenance import planned, prefix_recovery
from edge.packet import confirmed_partial_capture as partial
from edge.packet.feature_evidence import MIGRATION_013_FIELDS
from tests import test_planned_maintenance as maintenance
from tests.test_planned_prefix_recovery import (
    prefix_db, maintenance_db, inspect as prefix_inspect, apply as prefix_apply,
)


@pytest.fixture(autouse=True)
def migration_dirs(tmp_path, monkeypatch):
    old, new = tmp_path / "through-012", tmp_path / "through-013"
    old.mkdir()
    new.mkdir()
    for source in MIGRATIONS_DIR.glob("*.sql"):
        version = int(source.name.split("_", 1)[0])
        if version <= 12:
            shutil.copyfile(source, old / source.name)
        if version <= 13:
            shutil.copyfile(source, new / source.name)
    monkeypatch.setattr(maintenance, "MIGRATIONS_DIR", old)
    return new


def upgrade(conn, directory, migration_dirs):
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 12
    before = planned._rows(conn, "SELECT * FROM packet_feature_logs ORDER BY id")
    conn.commit()
    result = apply_migrations(directory / "iot.db", migration_dirs)
    assert result.applied_versions == [13]
    after = planned._rows(conn, "SELECT * FROM packet_feature_logs ORDER BY id")
    assert [{k: v for k, v in row.items() if k not in MIGRATION_013_FIELDS} for row in after] == before
    assert all(all(row[key] is None for key in MIGRATION_013_FIELDS) for row in after)


def unicode_features(conn):
    conn.execute("UPDATE packet_feature_logs SET capture_scope=?", ("관측 원본",))
    conn.commit()


def measured(conn, segment):
    conn.execute("UPDATE packet_feature_logs SET broker_target_ip='192.168.0.20',"
                 "broker_target_port=1883,broker_target_syn_count=0 WHERE capture_segment_id=?", (segment,))


def test_ready_source_seal_survives_real_013_without_rewriting(maintenance_db, migration_dirs):
    conn, _, directory = maintenance_db
    unicode_features(conn)
    operation = maintenance.ready(conn)
    original = deepcopy(operation)
    before = planned._bound_source(conn, operation)
    upgrade(conn, directory, migration_dirs)
    changes = conn.total_changes
    assert planned._bound_source(conn, operation) == before
    assert planned.get_operation(conn, operation["operation_id"]) == original
    assert conn.total_changes == changes
    with pytest.raises(sqlite3.IntegrityError, match="source Features are sealed"):
        conn.execute("UPDATE packet_feature_logs SET total_bytes=total_bytes+1 WHERE id=1")
    conn.rollback()


@pytest.mark.parametrize("mutation", ["feature", "non_null", "unknown_null", "segment", "identity"])
def test_legacy_source_compatibility_does_not_hide_corruption(maintenance_db, migration_dirs, mutation):
    conn, _, directory = maintenance_db
    operation = maintenance.ready(conn)
    upgrade(conn, directory, migration_dirs)
    # Simulate corruption behind the independent immutable-source trigger layer.
    conn.execute("DROP TRIGGER trg_planned_maintenance_source_feature_update")
    if mutation == "feature":
        conn.execute("UPDATE packet_feature_logs SET total_bytes=101 WHERE id=1")
    elif mutation == "non_null":
        measured(conn, 1)
    elif mutation == "unknown_null":
        conn.execute("ALTER TABLE packet_feature_logs ADD COLUMN unapproved_null TEXT")
    elif mutation == "identity":
        conn.execute("UPDATE packet_feature_logs SET id=99 WHERE id=1")
    else:
        conn.execute("DROP TRIGGER trg_planned_maintenance_source_segment_update")
        conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE id=1")
    with pytest.raises(planned.PlannedMaintenanceError):
        planned._bound_source(conn, operation)


def test_regular_resume_survives_013_without_rewriting_seals(maintenance_db, migration_dirs):
    conn, _, directory = maintenance_db
    unicode_features(conn)
    operation = maintenance.ready(conn)
    plan = maintenance.resume_plan(conn, operation)
    # Include non-ASCII target rows before producing the actual sealed plan.
    conn.execute("UPDATE packet_feature_logs SET capture_scope=? WHERE capture_segment_id=?",
                 ("대상 원본", plan["first_target_evidence"]["segment"]["id"]))
    conn.commit()
    plan = planned.inspect_resume(conn, operation["operation_id"], target_session_id=maintenance.TARGET,
        current_boot_id=maintenance.NEW_BOOT, time_synchronized=True, now=maintenance.utc(75))
    original = maintenance.apply(conn, plan, directory)
    expected = planned.approved_intervals(conn)
    upgrade(conn, directory, migration_dirs)
    changes = conn.total_changes
    assert planned.approved_intervals(conn) == expected
    assert planned.get_resume_audit(conn, operation["operation_id"]) == original
    assert maintenance.apply(conn, plan, directory) == original
    assert conn.total_changes == changes


@pytest.mark.parametrize("location", ["first", "later_prefix", "successor"])
@pytest.mark.parametrize("mutation", [None, "non_null", "feature", "segment", "unknown_null", "identity"])
def test_prefix_old_seals_bind_target_and_successor(prefix_db, migration_dirs, location, mutation):
    conn, directory, operation, ids = prefix_db
    conn.execute("UPDATE packet_feature_logs SET capture_scope=? WHERE id>2", ("재시작 원본",))
    conn.commit()
    plan = prefix_inspect(conn, operation)
    original = prefix_apply(conn, plan, directory)
    expected = planned.approved_intervals(conn)
    upgrade(conn, directory, migration_dirs)
    if mutation is None:
        changes = conn.total_changes
        assert planned.approved_intervals(conn) == expected
        assert prefix_recovery.validate_prefix_audit(conn, operation, plan) is None
        assert planned.get_resume_audit(conn, operation["operation_id"]) == original
        assert prefix_apply(conn, plan, directory) == original
        assert conn.total_changes == changes
        return
    segment = {"first": ids["normal"][0], "later_prefix": ids["normal"][1],
               "successor": ids["successor_segment"]}[location]
    if mutation == "non_null":
        measured(conn, segment)
    elif mutation == "feature":
        conn.execute("UPDATE packet_feature_logs SET total_bytes=101 WHERE capture_segment_id=?", (segment,))
    elif mutation == "identity":
        conn.execute("UPDATE packet_feature_logs SET id=id+100 WHERE capture_segment_id=?", (segment,))
    elif mutation == "segment":
        conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE id=?", (segment,))
    else:
        conn.execute("ALTER TABLE packet_feature_logs ADD COLUMN unapproved_null TEXT")
    with pytest.raises(planned.PlannedMaintenanceError):
        planned.approved_intervals(conn)
    with pytest.raises(planned.PlannedMaintenanceError):
        prefix_recovery.validate_prefix_audit(conn, operation, plan)


@pytest.mark.parametrize("initial_measured", [False, True])
def test_current_full_seals_cannot_fall_back_after_broker_change(maintenance_db, migration_dirs, initial_measured):
    conn, _, directory = maintenance_db
    upgrade(conn, directory, migration_dirs)
    operation = maintenance.ready(conn)
    plan = maintenance.resume_plan(conn, operation)
    target = plan["first_target_evidence"]["segment"]["id"]
    if initial_measured:
        measured(conn, target)
        conn.commit()
        plan = planned.inspect_resume(conn, operation["operation_id"], target_session_id=maintenance.TARGET,
            current_boot_id=maintenance.NEW_BOOT, time_synchronized=True, now=maintenance.utc(75))
    original = maintenance.apply(conn, plan, directory)
    assert planned.approved_intervals(conn)
    if initial_measured:
        conn.execute("UPDATE packet_feature_logs SET broker_target_ip=NULL,broker_target_port=NULL,"
                     "broker_target_syn_count=NULL WHERE capture_segment_id=?", (target,))
    else:
        measured(conn, target)
    with pytest.raises(planned.PlannedMaintenanceError):
        planned.approved_intervals(conn)
    assert dict(conn.execute("SELECT * FROM planned_maintenance_resumes").fetchone())["plan_sha256"] == original["plan_sha256"]


@pytest.fixture
def partial_proof(maintenance_db, monkeypatch):
    """Prepare and seal v2 evidence using real files on the pre-013 feature schema."""
    from backend.app import config
    from edge.packet.pcap_naming import build_pcap_filename
    conn, source, directory = maintenance_db
    failed = conn.execute("SELECT id FROM packet_capture_segments WHERE window_start=?", (maintenance.utc(10),)).fetchone()[0]
    name = build_pcap_filename(session_id=maintenance.SOURCE, interface="eth0",
        window_start=maintenance.BASE + timedelta(seconds=10),
        window_end=maintenance.BASE + timedelta(seconds=20), tmp=False)
    conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (failed,))
    conn.execute("UPDATE packet_capture_segments SET status='FAILED',error_code='PARTIAL_CAPTURE',"
                 "error_message='tcpdump kernel loss',file_name=?,packet_count=NULL WHERE id=?", (name, failed))
    healthy = maintenance.add_segment(conn, source, 20)
    unicode_features(conn)
    path = directory / name
    path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    metadata = dict(schema_version="packet-capture-diagnostics-v1", session_id=maintenance.SOURCE,
        capture_interface="eth0", window_start=maintenance.utc(10), window_end=maintenance.utc(20),
        pcap_file_name=name, expected_pcap_file_name=name, success=False, error_code="PARTIAL_CAPTURE",
        file_validation_error=None, completed_full_window=True, terminated_cleanly=True, exit_code=-15,
        stderr_complete=True, packets_captured=0, packets_received=1, packets_dropped=1,
        packets_dropped_by_interface=None, drop_status="observed_loss")
    path.with_suffix(".pcap.capture.json").write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(config, "settings", config.settings.model_copy(update={"pcap_failed_dir": str(directory)}))
    checkpoints = [{**row, "last_completed_window_end": maintenance.utc(10), "last_processed_id": 1}
                   for row in planned._rows(conn, "SELECT * FROM detector_checkpoints WHERE source_table='packet_feature_logs'")]
    engine = create_engine(f"sqlite:///{directory / 'iot.db'}")
    try:
        with Session(engine) as db:
            evidence = partial.prepare_partial_capture(db, maintenance.utc(10),
                maintenance.BASE + timedelta(seconds=30), checkpoints)
    finally:
        engine.dispose()
    assert evidence is not None
    audit = {key: evidence[key] for key in ("status", "reason", "window_start", "window_end")}
    audit.update(source_session_id=maintenance.SOURCE, target_session_id=maintenance.SOURCE,
                 evidence_json=json.dumps(evidence), plan_sha256=partial.digest(evidence))
    assert partial.validate_partial_evidence(conn, audit) == evidence
    features = partial.rows(conn, "SELECT * FROM packet_feature_logs WHERE capture_segment_id=:id", {"id": healthy})
    assert evidence["target_features_sha256"] == partial.digest(features)
    assert evidence["target_features_sha256"] != planned._digest(features)
    # This proof is portable even before the later Migration016 audit table exists.
    sealed = directory / "partial-v2-evidence.json"
    sealed.write_text(json.dumps(audit), encoding="utf-8")
    return conn, directory, audit, evidence, healthy, failed, sealed


@pytest.mark.parametrize("mutation", [None, "non_null", "feature", "unknown_null", "healthy_segment", "failed_segment", "source", "identity"])
def test_partial_v2_legacy_seal_keeps_ascii_encoding_and_all_bindings(partial_proof, migration_dirs, mutation):
    conn, directory, audit, evidence, healthy, failed, sealed = partial_proof
    original = sealed.read_bytes()
    upgrade(conn, directory, migration_dirs)
    if mutation == "non_null":
        measured(conn, healthy)
    elif mutation == "feature":
        conn.execute("UPDATE packet_feature_logs SET total_bytes=101 WHERE capture_segment_id=?", (healthy,))
    elif mutation == "identity":
        conn.execute("UPDATE packet_feature_logs SET id=id+100 WHERE capture_segment_id=?", (healthy,))
    elif mutation == "unknown_null":
        conn.execute("ALTER TABLE packet_feature_logs ADD COLUMN unapproved_null TEXT")
    elif mutation in ("healthy_segment", "failed_segment"):
        conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE id=?",
                     (healthy if mutation == "healthy_segment" else failed,))
    elif mutation == "source":
        conn.execute("UPDATE packet_capture_sessions SET capture_interface='eth1'")
    changes = conn.total_changes
    result = partial.validate_partial_evidence(conn, audit)
    assert result == (evidence if mutation is None else None)
    assert conn.total_changes == changes
    assert json.loads(sealed.read_text(encoding="utf-8")) == audit
    assert sealed.read_bytes() == original


@pytest.mark.parametrize("failed_target", [False, True])
@pytest.mark.parametrize("mutation", [None, "non_null", "feature", "segment", "session", "identity", "unknown_null"])
def test_bounded_replay_caller_keeps_original_manifest_and_envelope(maintenance_db, migration_dirs, failed_target, mutation):
    from edge.detection.packet_checkpoint_recovery import attach_plan_sha256
    from edge.detection.packet_checkpoint_recovery_repository import bounded_replay_target_evidence
    from edge.orchestration.run_detection_orchestrator import _bounded_replay_audit_matches
    from tests.test_planned_prefix_recovery import late_tail
    conn, _, directory = maintenance_db
    target = maintenance.add_session(conn, maintenance.TARGET, 60, status="FAILED" if failed_target else "COMPLETED")
    first = maintenance.add_segment(conn, target, 60)
    maintenance.add_segment(conn, target, 70)
    if failed_target:
        late_tail(conn, target, 80)
    conn.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE id=?", (maintenance.utc(81 if failed_target else 80), target))
    unicode_features(conn)
    session = planned._one(conn, "SELECT * FROM packet_capture_sessions WHERE id=:id", {"id": target})
    segments = planned._rows(conn, "SELECT * FROM packet_capture_segments WHERE capture_session_id=:id ORDER BY window_start,id", {"id": target})
    features = planned._rows(conn, "SELECT f.* FROM packet_feature_logs f JOIN packet_capture_segments s ON s.id=f.capture_segment_id WHERE s.capture_session_id=:id ORDER BY f.id", {"id": target})
    bound = bounded_replay_target_evidence(session, segments, features, allow_failed_target_session=failed_target)
    assert bound is not None
    plan = attach_plan_sha256({"mode": "bounded-replay", "bounded_replay": bound,
        "allow_failed_target_session": failed_target,
        **({"failed_target_tail": bound["failed_target_tail"]} if failed_target else {}),
        "target_session_id": maintenance.TARGET, "current_session_id": maintenance.SOURCE,
        "detector_name": "packet_rule", "source_table": "packet_feature_logs", "sessions_between": [],
        "checkpoint": {"before": {"last_processed_id": 2, "last_completed_window_end": maintenance.utc(20)},
                       "after": {"last_processed_id": 2, "last_completed_window_end": maintenance.utc(60)}}}, generated_at=maintenance.BASE)
    candidate = {"status": session["status"], "target_capture_session_id": maintenance.TARGET,
        "current_capture_session_id": maintenance.SOURCE, "detector_name": "packet_rule", "source_table": "packet_feature_logs",
        "last_processed_id_before": 2, "last_processed_id_after": 2,
        "last_completed_window_end_before": maintenance.utc(20), "skipped_session_count": 0, "skipped_processable_session_count": 0}
    original = deepcopy(plan)
    engine = create_engine(f"sqlite:///{directory / 'iot.db'}")
    def valid():
        with Session(engine) as db:
            return _bounded_replay_audit_matches(db, candidate, plan,
                maintenance.BASE + timedelta(seconds=60), maintenance.BASE + timedelta(seconds=20))
    try:
        assert valid()
        upgrade(conn, directory, migration_dirs)
        if mutation == "non_null":
            measured(conn, first)
        elif mutation == "feature":
            conn.execute("UPDATE packet_feature_logs SET total_bytes=101 WHERE capture_segment_id=?", (first,))
        elif mutation == "identity":
            conn.execute("UPDATE packet_feature_logs SET id=id+100 WHERE capture_segment_id=?", (first,))
        elif mutation == "segment":
            conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE id=?", (first,))
        elif mutation == "session":
            conn.execute("UPDATE packet_capture_sessions SET ended_at=? WHERE id=?", (maintenance.utc(82), target))
        elif mutation == "unknown_null":
            conn.execute("ALTER TABLE packet_feature_logs ADD COLUMN unapproved_null TEXT")
        conn.commit()
        assert valid() is (mutation is None)
        assert plan == original
    finally:
        engine.dispose()
