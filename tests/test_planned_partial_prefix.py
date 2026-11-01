"""Explicit partial-prefix admission never authorizes its loss checkpoint jump."""
from contextlib import closing
from dataclasses import asdict
from datetime import timedelta
import json
import sqlite3
import struct

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app import config
from edge.maintenance import planned as p
from edge.maintenance import run_planned_maintenance as cli
from edge.packet import confirmed_partial_capture as partial
from edge.packet.capture_policy import CapturePolicy, CaptureEligibilitySegment, is_capture_eligible
from edge.packet.pcap_naming import build_pcap_filename
from tests.test_planned_maintenance import BASE, TARGET, add_segment, add_session, utc, protected
from tests.test_planned_maintenance_cli import runner, ready_target, raw_status


@pytest.fixture
def case(runner, monkeypatch):
    instance, system, directory = runner
    operation = ready_target(instance, system)
    with sqlite3.connect(instance.database) as conn:
        failed = add_segment(conn, 2, 70, "FAILED")
        healthy = add_segment(conn, 2, 80)
        name = build_pcap_filename(session_id=TARGET, interface="eth0",
            window_start=BASE + timedelta(seconds=70), window_end=BASE + timedelta(seconds=80), tmp=False)
        actual = (BASE + timedelta(seconds=72.153811)).isoformat()
        conn.execute("UPDATE packet_capture_segments SET file_name=?,error_code='PARTIAL_CAPTURE',"
                     "error_message='capture timing excluded by policy',actual_capture_started_at=?,"
                     "start_delay_seconds=2.153811,captured_duration_seconds=7.846189,packet_count=NULL WHERE id=?",
                     (name, actual, failed))
    path = directory / name
    path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    metadata = dict(schema_version="packet-capture-diagnostics-v2", session_id=TARGET, capture_interface="eth0",
        window_start=utc(70), window_end=utc(80), pcap_file_name=name, expected_pcap_file_name=name,
        success=False, error_code="PARTIAL_CAPTURE", file_validation_error=None, completed_full_window=True,
        terminated_cleanly=True, exit_code=-15, stderr_complete=True, packets_captured=0, packets_received=0,
        packets_dropped=0, packets_dropped_by_interface=None, drop_status="no_kernel_drops_reported",
        quality_failure_reason="start_delay_exceeds_policy", capture_policy=asdict(CapturePolicy()),
        actual_capture_started_at=actual, capture_stop_requested_at=utc(80), capture_process_exited_at=utc(80),
        start_delay_seconds=2.153811, captured_duration_seconds=7.846189, stderr_error=None)
    path.with_suffix(".pcap.capture.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(config, "settings", config.settings.model_copy(update={"pcap_failed_dir": str(directory)}))
    system.elapsed = 90
    arguments = dict(operation_id=operation, target_session_id=TARGET, failed_segment_id=failed,
                     approved_by="woomin", reason="Drain the intact prefix before explicit recorded loss")
    return instance, system, directory, arguments, path, healthy


def preview(case):
    return case[0].dry_run_partial_prefix(**case[3])


def recover(case, **kwargs):
    return case[0].recover_partial_prefix(**case[3], artifact_dir=case[2] / "artifacts",
                                         timeout=0, verify_timeout=0, **kwargs)


def add_late_partial(case, start, *, successor=True):
    """Another independently retained timing failure after the fixed horizon."""
    instance, _, directory, _, template, _ = case
    name = build_pcap_filename(session_id=TARGET, interface="eth0", window_start=BASE + timedelta(seconds=start),
                               window_end=BASE + timedelta(seconds=start + 10), tmp=False)
    actual = (BASE + timedelta(seconds=start + 3.062781)).isoformat()
    with sqlite3.connect(instance.database) as conn:
        failed = add_segment(conn, 2, start, "FAILED")
        conn.execute("UPDATE packet_capture_segments SET file_name=?,error_code='PARTIAL_CAPTURE',"
                     "error_message='second timing failure',actual_capture_started_at=?,"
                     "start_delay_seconds=3.062781,captured_duration_seconds=6.937219,packet_count=NULL WHERE id=?",
                     (name, actual, failed))
        if successor:
            add_segment(conn, 2, start + 10)
    path = directory / name
    path.write_bytes(template.read_bytes())
    diagnostic = json.loads(template.with_suffix(".pcap.capture.json").read_text())
    diagnostic.update(window_start=utc(start), window_end=utc(start + 10), pcap_file_name=name,
        expected_pcap_file_name=name, actual_capture_started_at=actual, capture_stop_requested_at=utc(start + 10),
        capture_process_exited_at=utc(start + 10), start_delay_seconds=3.062781, captured_duration_seconds=6.937219)
    path.with_suffix(".pcap.capture.json").write_text(json.dumps(diagnostic))
    return failed, path


def snapshot(instance):
    with closing(sqlite3.connect(instance.database)) as conn:
        return (protected(conn), conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name").fetchall(),
                conn.execute("SELECT * FROM planned_maintenance_operations").fetchall(),
                conn.execute("SELECT * FROM planned_maintenance_resumes").fetchall(),
                conn.execute("SELECT * FROM packet_detection_gaps").fetchall())


def test_explicit_preview_and_apply_preserve_raw_and_only_jump_downtime(case):
    instance, system, _, arguments, path, _ = case
    before = snapshot(instance)
    events = system.events[:]
    plan = preview(case)
    assert snapshot(instance) == before and system.events == events
    proof = plan["partial_prefix_recovery"]["capture_proof"]
    assert "checkpoints_before" not in proof
    assert plan["maintenance_end"] == utc(60)
    assert proof["window_start"] == utc(70) and proof["window_end"] == utc(80)
    assert plan["partial_prefix_recovery"]["admission_horizon_end"] == utc(90)
    assert plan["partial_prefix_recovery"]["prefix_snapshot"]["segment_count"] == 3
    assert plan["partial_prefix_recovery"]["failed_segment_id"] == arguments["failed_segment_id"]
    with pytest.raises(p.PlannedMaintenanceError, match="healthy"):
        instance.dry_run(arguments["operation_id"])
    result = recover(case)
    assert result["result"] == "COMMITTED_HOLD" and result["verification"]["result"] == "WAIT"
    assert "real016" in result["verification"]["reason"]
    after = snapshot(instance)
    assert before[0] == after[0] and not after[4]
    for row in after[1]:
        prior = next(item for item in before[1] if item[0] == row[0])
        expected = (prior[0], prior[1], prior[2], utc(60), utc(60)) if row[0] in p.PACKET_DETECTORS else prior
        assert row == expected
    assert len(after[3]) == 1 and raw_status(instance) == "RESUMED"
    failed = proof["failed_segments"][0]["segment"]
    assert not is_capture_eligible(CaptureEligibilitySegment(failed["status"], failed["error_code"],
        failed["start_delay_seconds"], failed["captured_duration_seconds"]), CapturePolicy()).eligible
    assert path.exists()


def test_ordinary_apply_cannot_consume_explicit_partial_plan(case):
    instance = case[0]
    plan = preview(case)
    before = snapshot(instance)
    with cli.connection(instance.database) as conn:
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(p.PlannedMaintenanceError, match="explicit partial-prefix"):
            p.apply_resume(conn, plan, now=utc(105), backup_path=str(case[2] / "backup.db"), backup_sha256="a" * 64)
    assert snapshot(instance) == before


@pytest.mark.parametrize("mutation", ["missing_pcap", "missing_sidecar", "bad_pcap", "bad_diagnostics",
    "wrong_timing", "no_successor", "ready_successor", "failed_successor", "prefix_failure",
    "empty_prefix_without_traffic", "features_on_failure", "overlap", "wrong_selected_id", "wrong_target"])
def test_unqualified_or_additional_failure_never_consumes_ready(case, mutation):
    instance, _, _, arguments, path, healthy = case
    sidecar = path.with_suffix(".pcap.capture.json")
    if mutation == "missing_pcap": path.unlink()
    elif mutation == "missing_sidecar": sidecar.unlink()
    elif mutation == "bad_pcap": path.write_bytes(b"not a pcap")
    elif mutation == "bad_diagnostics":
        value = json.loads(sidecar.read_text()); value["stderr_complete"] = False
        sidecar.write_text(json.dumps(value))
    elif mutation == "wrong_selected_id": arguments["failed_segment_id"] = healthy
    elif mutation == "wrong_target": arguments["target_session_id"] = "55555555-5555-4555-8555-555555555555"
    else:
        with sqlite3.connect(instance.database) as conn:
            if mutation == "wrong_timing":
                conn.execute("UPDATE packet_capture_segments SET captured_duration_seconds=8 WHERE id=?", (arguments["failed_segment_id"],))
            elif mutation in ("no_successor", "ready_successor", "failed_successor"):
                conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id=?", (healthy,))
                if mutation == "no_successor": conn.execute("DELETE FROM packet_capture_segments WHERE id=?", (healthy,))
                else: conn.execute("UPDATE packet_capture_segments SET status=? WHERE id=?", ("READY" if mutation == "ready_successor" else "FAILED", healthy))
            elif mutation in ("prefix_failure", "empty_prefix_without_traffic"):
                conn.execute("DELETE FROM packet_feature_logs WHERE capture_segment_id IN (SELECT id FROM packet_capture_segments WHERE window_start=?)", (utc(60),))
                conn.execute("UPDATE packet_capture_segments SET status=? WHERE window_start=?", ("FAILED" if mutation == "prefix_failure" else "EMPTY", utc(60)))
            elif mutation == "features_on_failure":
                conn.execute("UPDATE packet_feature_logs SET capture_segment_id=? WHERE capture_segment_id=?", (arguments["failed_segment_id"], healthy))
            elif mutation == "overlap":
                other = add_session(conn, "55555555-5555-4555-8555-555555555555", 70, status="FAILED")
                conn.execute("UPDATE packet_capture_sessions SET capture_interface='wlan0' WHERE id=?", (other,))
                conn.execute("INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,"
                             "window_start,window_end,status,start_delay_seconds,captured_duration_seconds) "
                             "VALUES (?,'overlap.pcap','wlan0',?,?,'EMPTY',0,10)", (other, utc(70), utc(80)))
    before = snapshot(instance)
    with pytest.raises((p.PlannedMaintenanceError, cli.MaintenanceHold)):
        preview(case)
    result = recover(case)
    assert result["result"] == "WAIT" and snapshot(instance) == before and raw_status(instance) == "READY"


@pytest.mark.parametrize("change", ["pcap", "sidecar", "failed_row", "healthy_feature"])
def test_proof_race_during_backup_holds_without_any_transition(case, change):
    instance, _, _, arguments, path, healthy = case
    backup = instance.backup
    def changed(database, root):
        evidence = backup(database, root)
        if change == "pcap": path.write_bytes(path.read_bytes() + b"changed")
        elif change == "sidecar":
            sidecar = path.with_suffix(".pcap.capture.json")
            sidecar.write_text(sidecar.read_text() + " ")
        else:
            with sqlite3.connect(database) as conn:
                if change == "failed_row": conn.execute("UPDATE packet_capture_segments SET error_message='changed' WHERE id=?", (arguments["failed_segment_id"],))
                elif change == "healthy_feature": conn.execute("UPDATE packet_feature_logs SET packet_count=3 WHERE capture_segment_id=?", (healthy,))
        return evidence
    instance.backup = changed
    with pytest.raises(p.PlannedMaintenanceError): recover(case)
    assert raw_status(instance) == "READY"
    with sqlite3.connect(instance.database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM packet_detection_gaps").fetchone()[0] == 0
        assert conn.execute("SELECT DISTINCT last_completed_window_end FROM detector_checkpoints").fetchall() == [(utc(20),)]


def test_healthy_append_is_allowed_and_files_are_hashed_before_writer(case, monkeypatch):
    instance = case[0]
    original_file_proof, backup = partial._file_proof, instance.backup
    calls = []
    def file_proof(*args, **kwargs):
        with sqlite3.connect(instance.database, timeout=0) as writer:
            writer.execute("BEGIN IMMEDIATE")
        calls.append(args[0])
        return original_file_proof(*args, **kwargs)
    monkeypatch.setattr(partial, "_file_proof", file_proof)
    def append(database, root):
        evidence = backup(database, root)
        with sqlite3.connect(database) as conn: add_segment(conn, 2, 90)
        return evidence
    instance.backup = append
    assert recover(case)["result"] == "COMMITTED_HOLD"
    assert len(calls) == 2


@pytest.mark.parametrize("known", [True, False])
def test_new_failure_after_horizon_during_backup_does_not_widen_admission(case, known):
    instance, system, _, _, _, _ = case
    plan = preview(case)
    backup = instance.backup
    def append(database, root):
        evidence = backup(database, root)
        if known:
            add_late_partial(case, 90)
        else:
            with sqlite3.connect(database) as conn:
                add_segment(conn, 2, 90, "FAILED")
        system.elapsed = 100
        return evidence
    instance.backup = append
    result = recover(case)
    assert result["result"] == "COMMITTED_HOLD"
    assert result["verification"]["result"] == ("WAIT" if known else "HOLD")
    assert result["audit"]["plan_sha256"] == plan["plan_sha256"]
    with sqlite3.connect(instance.database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM packet_detection_gaps").fetchone()[0] == 0
        assert conn.execute("SELECT last_processed_id,last_completed_window_end FROM detector_checkpoints "
                            "WHERE source_table='packet_feature_logs'").fetchall() == [(2, utc(60)), (2, utc(60))]
    if known:
        assert result["verification"]["gap_verification"]["required_boundary"] == utc(100)
        assert len(result["verification"]["gap_verification"]["pending_segment_ids"]) == 2


@pytest.mark.parametrize("mutation", ["middle_feature", "middle_segment", "horizon"])
def test_entire_bounded_prefix_is_sealed_not_just_first_feature(case, mutation):
    instance = case[0]
    with sqlite3.connect(instance.database) as conn:
        conn.execute("UPDATE packet_capture_sessions SET started_at=?,first_window_start=?,capture_gap_end=? "
                     "WHERE session_id=?", (utc(50), utc(50), utc(50), TARGET))
        add_segment(conn, 2, 50)
    plan = preview(case)
    with cli.connection(instance.database) as conn:
        if mutation == "middle_feature":
            conn.execute("UPDATE packet_feature_logs SET packet_count=3 WHERE window_start=?", (utc(60),))
        elif mutation == "middle_segment":
            conn.execute("UPDATE packet_capture_segments SET packet_count=3 WHERE window_start=?", (utc(60),))
        else:
            plan["partial_prefix_recovery"]["admission_horizon_end"] = utc(100)
            plan["plan_sha256"] = p.calculate_plan_sha256(plan)
        before = snapshot(instance)
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(p.PlannedMaintenanceError):
            p.apply_partial_prefix(conn, plan, now=utc(105), backup_path=str(case[2] / "backup.db"), backup_sha256="a" * 64)
    assert snapshot(instance) == before and raw_status(instance) == "READY"


def test_committed_retry_is_bound_and_never_reapplies_or_rehashes(case, monkeypatch):
    first = recover(case)
    before = snapshot(case[0])
    monkeypatch.setattr(partial, "_file_proof", lambda *_a, **_k: pytest.fail("committed retry must not hash files"))
    case[4].unlink()
    case[4].with_suffix(".pcap.capture.json").unlink()
    again = recover(case)
    assert again["audit"]["operation_id"] == first["audit"]["operation_id"] and snapshot(case[0]) == before
    case[3]["reason"] = "different approval"
    assert recover(case)["result"] == "HOLD"
    assert snapshot(case[0]) == before


def test_loss_audit_cannot_be_invented_by_advancing_checkpoints(case):
    result = recover(case)
    plan = json.loads(result["audit"]["plan_json"])
    with sqlite3.connect(case[0].database) as conn:
        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE source_table='packet_feature_logs'", (utc(80),))
    with pytest.raises(p.PlannedMaintenanceError, match="without a valid016"):
        case[0].verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)


def test_empty_prefix_is_preserved_and_jump_stays_at_first_window(case):
    with sqlite3.connect(case[0].database) as conn:
        conn.execute("UPDATE packet_capture_sessions SET started_at=?,first_window_start=?,capture_gap_end=? "
                     "WHERE session_id=?", (utc(50), utc(50), utc(50), TARGET))
        empty = add_segment(conn, 2, 50, "EMPTY")
    plan = preview(case)
    assert plan["maintenance_end"] == utc(50)
    assert plan["first_target_evidence"]["empty_prefix"][0]["id"] == empty
    assert recover(case)["result"] == "COMMITTED_HOLD"
    with sqlite3.connect(case[0].database) as conn:
        assert conn.execute("SELECT last_processed_id,last_completed_window_end FROM detector_checkpoints "
                            "WHERE source_table='packet_feature_logs'").fetchall() == [(2, utc(50)), (2, utc(50))]


def test_maintenance_exclusion_survives_retention_and_later_session_lifecycle(case):
    recover(case)
    case[4].unlink()
    case[4].with_suffix(".pcap.capture.json").unlink()
    with sqlite3.connect(case[0].database) as conn:
        conn.execute("UPDATE packet_capture_sessions SET status='FAILED',ended_at=? WHERE session_id=?", (utc(90), TARGET))
        add_session(conn, "55555555-5555-4555-8555-555555555555", 90)
        intervals = p.approved_intervals(conn)
        assert [(item["window_start"], item["window_end"]) for item in intervals] == [(utc(20), utc(60))]
    assert recover(case)["result"] == "HOLD"


@pytest.mark.parametrize("changed_diagnostics,outbound_prefix,later_failure", [
    (False, False, None), (False, True, None), (True, False, None),
    (False, False, "preexisting"), (False, False, "preexisting_corrupt"),
    (False, False, "preexisting_cp_passed"), (False, False, "preexisting_duplicate"),
    (False, False, "preexisting_legacy"), (False, False, "preexisting_rewind_id"),
    (False, False, "preexisting_rewind_boundary"),
    (False, False, "between_passes_pending"), (False, False, "between_passes_audited")])
def test_real_pipeline_consumes_prefix_then_records_only_partial_loss_and_fresh_progress(
        case, monkeypatch, changed_diagnostics, outbound_prefix, later_failure):
    from edge.detection.mqtt_adapters import MqttFeatureRuleStage, MqttMessageRuleStage
    from edge.detection.packet_rule_detector import PacketRuleDetectorStage
    from edge.features.run_mqtt_feature_builder import run_producer_cycle
    from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
    from edge.orchestration import run_detection_orchestrator as orchestrator
    from edge.orchestration.stage_registry import StageRegistry, ConfiguredStage
    from tests.test_planned_maintenance_processing import real_packet_if_with_normal_predictions
    from tests.device_policy_support import insert_revision_raw
    instance, system, _, arguments, _, healthy = case
    second = None
    if later_failure and later_failure.startswith("preexisting"):
        second, _ = add_late_partial(case, 90)
        system.elapsed = 110
    with sqlite3.connect(instance.database) as conn:
        insert_revision_raw(conn, device_id="esp32_01", registration_state="ACTIVE", effective_from=utc(-10))
        for start in (60, 70, 80):
            conn.execute("INSERT INTO mqtt_logs(device_id,topic,payload,payload_size,received_at,is_json_valid,is_topic_valid) "
                         "VALUES ('esp32_01','iot/esp32_01/sensor','{}',2,?,1,1)", (utc(start + 1),))
        prefix_id = conn.execute("SELECT id FROM packet_feature_logs WHERE window_start=?", (utc(60),)).fetchone()[0]
        tail_id = conn.execute("SELECT id FROM packet_feature_logs WHERE capture_segment_id=?", (healthy,)).fetchone()[0]
        if outbound_prefix:
            conn.execute("UPDATE packet_feature_logs SET direction='OUTBOUND' WHERE id=?", (prefix_id,))
    result = recover(case)
    plan = json.loads(result["audit"]["plan_json"])
    engine = create_engine(f"sqlite:///{instance.database}")
    factory = sessionmaker(bind=engine)
    packet_if, predicted = real_packet_if_with_normal_predictions()
    stages = (MqttFeatureRuleStage(), MqttMessageRuleStage(),
              PacketFeatureReadyStage(PacketRuleDetectorStage(capture_policy=CapturePolicy())),
              PacketFeatureReadyStage(packet_if))
    registry = StageRegistry(tuple(ConfiguredStage(stage.detector_name, stage, True) for stage in stages))
    monkeypatch.setattr(orchestrator, "settings", orchestrator.settings.model_copy(update={"packet_confirmed_gap_policy_enabled": True}))
    def cycle():
        value = orchestrator.run_orchestration_cycle(session_factory=factory, registry=registry)
        assert value.status == orchestrator.CYCLE_COMPLETED
        return value
    try:
        run_producer_cycle(session_factory=factory, now=BASE + timedelta(seconds=111 if second else 91))
        assert cycle().cutoff == BASE + timedelta(seconds=60)
        assert cycle().cutoff == BASE + timedelta(seconds=70)
        with factory() as db:
            pair = {row[0]: (row[1], row[2]) for row in db.execute(text("SELECT detector_name,last_processed_id,"
                    "last_completed_window_end FROM detector_checkpoints WHERE source_table='packet_feature_logs'"))}
            assert pair == {"packet_rule": (2 if outbound_prefix else prefix_id, utc(70)),
                            "packet_if": (prefix_id, utc(70))}
            assert db.execute(text("SELECT COUNT(*) FROM packet_detection_gaps")).scalar() == 0
        assert instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)["result"] == "WAIT"
        if changed_diagnostics:
            sidecar = case[4].with_suffix(".pcap.capture.json")
            sidecar.write_text(sidecar.read_text() + " ")
        assert cycle().cutoff == BASE + timedelta(seconds=80)
        with factory() as db:
            audit = dict(db.execute(text("SELECT * FROM packet_detection_gaps")).mappings().one())
            evidence = json.loads(audit["evidence_json"])
            assert (audit["window_start"], audit["window_end"], audit["status"]) == (utc(70), utc(80), "UNINSPECTED")
            assert all(item["last_processed_id"] == (2 if outbound_prefix and item["detector_name"] == "packet_rule" else prefix_id)
                       and item["last_completed_window_end"] == utc(70)
                       for item in evidence["checkpoints_before"])
            assert partial.validate_partial_evidence(db, audit) == evidence
        if changed_diagnostics:
            with pytest.raises(p.PlannedMaintenanceError, match="file hashes differ"):
                instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)
            return
        assert cycle().cutoff == BASE + timedelta(seconds=90)
        with factory() as db:
            assert db.execute(text("SELECT last_processed_id FROM detector_checkpoints WHERE source_table='packet_feature_logs'")).scalars().all() == [tail_id, tail_id]
        frame = 90
        if second:
            if later_failure in ("preexisting_corrupt", "preexisting_cp_passed"):
                with sqlite3.connect(instance.database) as conn:
                    if later_failure == "preexisting_corrupt":
                        conn.execute("INSERT INTO packet_detection_gaps(source_session_id,target_session_id,window_start,window_end,"
                                     "status,reason,evidence_json,plan_sha256) VALUES (?,?,?,?,'UNINSPECTED','RECORDED_CAPTURE_GAP','{}',?)",
                                     (TARGET, TARGET, utc(90), utc(100), "a" * 64))
                    else:
                        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? "
                                     "WHERE source_table='packet_feature_logs'", (utc(100),))
                with pytest.raises(p.PlannedMaintenanceError, match="invalid or ambiguous|without a valid016"):
                    instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)
                return
            waiting = instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)
            assert waiting["result"] == "WAIT" and waiting["gap_verification"]["pending_segment_ids"] == [second]
            if later_failure == "preexisting_legacy":
                import hashlib
                from edge.packet.segment_gap_recovery import build_segment_gap_plan, apply_segment_gap_plan
                with cli.connection(instance.database) as conn:
                    name = conn.execute("SELECT file_name FROM packet_capture_segments WHERE id=?", (second,)).fetchone()[0]
                    retained = case[2] / name
                    approved = build_segment_gap_plan(conn, capture_session_id=TARGET, failed_segment_id=second,
                        approved_by="synthetic operator", reason="Explicit second loss", repository_commit="a" * 40,
                        database_path=str(instance.database), backup_path=str(case[2] / "legacy.backup.db"),
                        preserved_pcap_path=str(retained), pcap_sha256=hashlib.sha256(retained.read_bytes()).hexdigest())
                    conn.execute("BEGIN IMMEDIATE")
                    apply_segment_gap_plan(conn, approved, backup_sha256="b" * 64)
                    conn.commit()
            assert cycle().cutoff == BASE + timedelta(seconds=100)
            if later_failure != "preexisting_legacy":
                with factory() as db:
                    audit = dict(db.execute(text("SELECT * FROM packet_detection_gaps WHERE window_start=:start"),
                                           {"start": utc(90)}).mappings().one())
                    evidence = partial.validate_partial_evidence(db, audit)
                    assert evidence is not None
                    assert all(item["last_processed_id"] == tail_id for item in evidence["checkpoints_before"])
            if later_failure in ("preexisting_rewind_id", "preexisting_rewind_boundary"):
                with sqlite3.connect(instance.database) as conn:
                    if later_failure == "preexisting_rewind_id":
                        conn.execute("UPDATE detector_checkpoints SET last_processed_id=? WHERE source_table='packet_feature_logs'", (prefix_id,))
                    else:
                        conn.execute("UPDATE detector_checkpoints SET last_completed_window_end=? WHERE source_table='packet_feature_logs'", (utc(90),))
                with pytest.raises(p.PlannedMaintenanceError, match="rewound behind"):
                    instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)
                return
            if later_failure == "preexisting_duplicate":
                with sqlite3.connect(instance.database) as conn:
                    conn.execute("INSERT INTO packet_segment_gap_recoveries(operation_id,capture_session_id,failed_segment_id,"
                                 "window_start,window_end,plan_sha256,plan_json,approved_by,reason,repository_commit,database_path,"
                                 "backup_path,backup_sha256,preserved_pcap_path,pcap_sha256) VALUES (?,?,?,?,?,?,'{}','synthetic',"
                                 "'duplicate audit corruption',?,?,?,?,?,?)",
                                 ("66666666-6666-4666-8666-666666666666", TARGET, second, utc(90), utc(100), "a" * 64,
                                  "a" * 40, str(instance.database), str(case[2] / "backup.db"), "a" * 64, str(case[4]), "a" * 64))
                with pytest.raises(p.PlannedMaintenanceError, match="duplicate gap approvals"):
                    instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=0, partial_plan=plan)
                return
            assert cycle().cutoff == BASE + timedelta(seconds=110)
            frame = 110
        pending_second = False
        def advance():
            nonlocal frame, second, pending_second
            if pending_second:
                assert cycle().cutoff == BASE + timedelta(seconds=110)
                assert cycle().cutoff == BASE + timedelta(seconds=120)
                frame, pending_second = 120, False
                return
            if later_failure in ("between_passes_pending", "between_passes_audited") and frame == 100 and second is None:
                second, _ = add_late_partial(case, 100)
                system.elapsed = 106
                run_producer_cycle(session_factory=factory, now=BASE + timedelta(seconds=121))
                if later_failure == "between_passes_pending":
                    pending_second = True
                else:
                    assert cycle().cutoff == BASE + timedelta(seconds=110)
                    assert cycle().cutoff == BASE + timedelta(seconds=120)
                    frame = 120
                return
            with sqlite3.connect(instance.database) as conn:
                add_segment(conn, 2, frame)
            frame += 10
            system.elapsed = max(system.elapsed + 1, frame - 14)
            run_producer_cycle(session_factory=factory, now=BASE + timedelta(seconds=frame + 1))
            cycle()
        system.on_sleep = advance
        verified = instance.verify_progress(TARGET, p.REQUIRED_CHECKPOINTS, timeout=40, partial_plan=plan)
        assert verified["result"] == "PASS" and len(verified["snapshots"]) == 2
        if later_failure in ("between_passes_pending", "between_passes_audited"):
            assert [{item["boundary"] for item in row.values()} for row in verified["snapshots"]] == [{utc(130)}, {utc(140)}]
            assert verified["gap_verification"]["required_boundary"] == utc(110)
        with sqlite3.connect(instance.database) as conn:
            assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM packet_detection_gaps").fetchone()[0] == (2 if second and later_failure != "preexisting_legacy" else 1)
            assert conn.execute("SELECT COUNT(*) FROM packet_segment_gap_recoveries").fetchone()[0] == (1 if later_failure == "preexisting_legacy" else 0)
            assert conn.execute("SELECT status,error_code FROM packet_capture_segments WHERE id=?", (arguments["failed_segment_id"],)).fetchone() == ("FAILED", "PARTIAL_CAPTURE")
            assert conn.execute("SELECT COUNT(*) FROM packet_feature_logs WHERE capture_segment_id=?", (arguments["failed_segment_id"],)).fetchone()[0] == 0
        assert predicted
    finally:
        engine.dispose()


def test_parser_requires_explicit_partial_identity_and_operator():
    args = cli.build_parser().parse_args(["recover-partial-prefix", "--operation-id", "operation",
        "--target-session-id", TARGET, "--failed-segment-id", "99890", "--approved-by", "woomin", "--reason", "reviewed"])
    assert args.failed_segment_id == 99890 and args.command == "recover-partial-prefix"
