"""Real SQLite pipeline preserves raw data and drains an audited planned gap."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import csv
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.export_normal_features import export_normal_features
from ai.predict_packet_isolation_forest import PacketIFArtifact, PacketIFPrediction
from db.migration_runner import apply_migrations
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.detector_contract import DetectorRunResult
from edge.detection.mqtt_adapters import MqttFeatureRuleStage, MqttMessageRuleStage, MqttIsolationForestStage
from edge.detection.packet_rule_detector import PacketRuleDetectorStage
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.features.collect_feature_logs import produce_mqtt_features_until
from edge.features.run_mqtt_feature_builder import produce_once
from edge.maintenance.planned import (
    PlannedMaintenanceError, request_stop, finalize_stop, inspect_resume,
    apply_resume, REQUIRED_CHECKPOINTS,
)
from edge.maintenance.processing import dataset_maintenance_windows, overlaps_maintenance
from edge.orchestration.packet_stage_readiness import PacketFeatureReadyStage
from edge.orchestration.run_detection_orchestrator import run_orchestration_cycle, CYCLE_COMPLETED
from edge.orchestration.stage_registry import StageRegistry, ConfiguredStage
from edge.packet.capture_policy import CapturePolicy
from edge.trust.trust_score_v2 import apply_trust_score_v2_until
from tests.device_policy_support import insert_revision_raw
from tests.test_normal_collection_export import package
from ai.export_normal_collection import export_normal_collection

BASE = datetime(2026, 10, 5, tzinfo=timezone.utc)


def utc(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def insert(conn, table, **values):
    return conn.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})",
                        tuple(values.values())).lastrowid


def packet(conn, session, start):
    segment = insert(conn, "packet_capture_segments", capture_session_id=session,
                     file_name=f"window-{start}.pcap", capture_interface="eth0", window_start=utc(start),
                     window_end=utc(start + 10), status="PROCESSED", packet_count=2,
                     start_delay_seconds=0, captured_duration_seconds=10)
    return insert(conn, "packet_feature_logs", capture_segment_id=segment, device_id="esp32_01",
                  peer_ip="192.168.0.4", direction="INBOUND", window_start=utc(start), window_end=utc(start + 10),
                  packet_count=2, total_bytes=100, avg_packet_size=50, max_packet_size=50)


def feature(conn, start, count=2):
    return insert(conn, "feature_logs", device_id="esp32_01", window_start=utc(start), window_end=utc(start + 10),
                  publish_count=count, avg_payload_size=29, max_payload_size=29,
                  avg_message_interval=5, min_message_interval=5, topic_count=1)


def messages(conn, start, count=2, malformed=False):
    for offset in range(count):
        insert(conn, "mqtt_logs", device_id="esp32_01", topic="iot/esp32_01/sensor",
               payload="invalid" if malformed else '{"device_id":"esp32_01"}',
               payload_size=29, received_at=utc(start + offset % 10),
               is_json_valid=0 if malformed else 1, is_topic_valid=1)


@pytest.fixture
def prepared(tmp_path):
    path = tmp_path / "maintenance.db"
    apply_migrations(path)
    source, source_boot = str(uuid4()), str(uuid4())
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        insert(conn, "devices", device_id="esp32_01", ip_address="192.168.0.4", status="normal", trust_score=77)
        insert_revision_raw(conn, device_id="esp32_01", registration_state="ACTIVE", effective_from=utc(-10))
        source_pk = insert(conn, "packet_capture_sessions", session_id=source, capture_interface="eth0",
                           started_at=utc(0), first_window_start=utc(0), status="RUNNING")
        source_packet = packet(conn, source_pk, 0)
        source_feature = feature(conn, 0)
        messages(conn, 0)
        for detector, table in REQUIRED_CHECKPOINTS:
            last_id = {"mqtt_logs": 2, "feature_logs": source_feature,
                       "packet_feature_logs": source_packet, "detection_events": None}[table]
            insert(conn, "detector_checkpoints", detector_name=detector, source_table=table,
                   last_processed_id=last_id, last_completed_window_end=utc(10), updated_at=utc(10))
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        operation = request_stop(conn, approved_by="woomin", reason="planned reboot",
                                 source_session_id=source, source_boot_id=source_boot, now=BASE + timedelta(seconds=8))
        conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED',ended_at=? WHERE session_id=?",
                     (utc(11), source))
        finalize_stop(conn, operation["operation_id"], now=BASE + timedelta(seconds=12))
        conn.commit()
    engine = create_engine(f"sqlite:///{path}")
    factory = sessionmaker(bind=engine)
    try:
        yield path, factory, operation["operation_id"]
    finally:
        engine.dispose()


def resume(path, operation):
    target, target_boot = str(uuid4()), str(uuid4())
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        target_pk = insert(conn, "packet_capture_sessions", session_id=target, capture_interface="eth0",
                           started_at=utc(25), first_window_start=utc(30), status="RUNNING",
                           capture_gap_start=utc(10), capture_gap_end=utc(30))
        target_packet = packet(conn, target_pk, 30)
        conn.commit()
        plan = inspect_resume(conn, operation, target_session_id=target, current_boot_id=target_boot,
                              time_synchronized=True, now=BASE + timedelta(seconds=42))
        conn.execute("BEGIN IMMEDIATE")
        apply_resume(conn, plan, now=BASE + timedelta(seconds=42),
                     backup_path=str(path.with_suffix(".backup.db")), backup_sha256="a" * 64)
        conn.commit()
    return target_packet


def test_ready_holds_producer_without_consuming_raw_or_rewinding(prepared):
    path, factory, _ = prepared
    with closing(sqlite3.connect(path)) as conn:
        messages(conn, 10, malformed=True)
        conn.commit()
    with factory.begin() as db:
        assert produce_once(db, now=BASE + timedelta(seconds=40)) is None
        result = produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=40))
        assert result.completed_window_end_after == BASE + timedelta(seconds=10)
        assert result.last_processed_id_after == 2
        assert db.execute(text("SELECT COUNT(*) FROM mqtt_logs")).scalar() == 4
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar() == 1
        with pytest.raises(RuntimeError, match="holds processing"):
            MqttMessageRuleStage().run_until(db, cycle_range_start=BASE + timedelta(seconds=10),
                                            cycle_cutoff=BASE + timedelta(seconds=30))
        with pytest.raises(RuntimeError, match="holds processing"):
            apply_trust_score_v2_until(db, cycle_range_start=BASE + timedelta(seconds=10),
                                      cycle_cutoff=BASE + timedelta(seconds=30))
        assert overlaps_maintenance(dataset_maintenance_windows(db), BASE + timedelta(seconds=10),
                                    BASE + timedelta(seconds=20))


def test_resumed_producer_excludes_gap_but_keeps_raw_and_real_source_ids(prepared):
    path, factory, operation = prepared
    with closing(sqlite3.connect(path)) as conn:
        messages(conn, 10, 20, malformed=True)
        messages(conn, 20, 20, malformed=True)
        messages(conn, 30, 20)
        conn.commit()
    resume(path, operation)
    with factory.begin() as db:
        result = produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=40))
        assert result.created_feature_count == 1
        assert result.last_processed_id_after == 62
        assert db.execute(text("SELECT COUNT(*) FROM mqtt_logs")).scalar() == 62
        assert db.execute(text("SELECT window_start FROM feature_logs ORDER BY id")).scalars().all() == [utc(0), utc(30)]


def test_existing_feature_in_gap_is_not_sent_to_rules_or_if_and_export_excludes_it(prepared, tmp_path, monkeypatch):
    path, factory, operation = prepared
    with closing(sqlite3.connect(path)) as conn:
        feature(conn, 10, count=999)
        feature(conn, 20, count=2)
        feature(conn, 30, count=2)
        messages(conn, 10, malformed=True)
        conn.commit()
    resume(path, operation)
    calls = []

    def predict(row, _path):
        calls.append(row["window_start"])
        return {"is_anomaly": False}

    monkeypatch.setattr("edge.detection.mqtt_adapters.predict_feature_window", predict)
    with factory.begin() as db:
        for stage in (MqttFeatureRuleStage(), MqttMessageRuleStage(), MqttIsolationForestStage()):
            stage.run_until(db, cycle_range_start=BASE + timedelta(seconds=10), cycle_cutoff=BASE + timedelta(seconds=40))
        assert calls == [utc(30)]
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar() == 0
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar() == 4
        count = export_normal_features(db, tmp_path / "export.csv", limit=2)
        assert count == 2
        with (tmp_path / "export.csv").open() as file:
            assert [row["window_start"] for row in csv.DictReader(file)] == [utc(0), utc(30)]


class RecordingPacketIF:
    detector_name = "packet_if"
    source_table = "packet_feature_logs"

    def __init__(self):
        self.calls = []

    def run_until_for_capture_session(self, db, *, cycle_range_start, cycle_cutoff, expected_capture_session_id):
        self.calls.append((cycle_range_start, cycle_cutoff))
        before = checkpoints.get_detector_checkpoint(db, detector_name=self.detector_name, source_table=self.source_table)
        source_id = db.execute(text("SELECT MAX(id) FROM packet_feature_logs WHERE window_start>=:start AND window_end<=:end"),
                               {"start": cycle_range_start.isoformat().replace("+00:00", "Z"),
                                "end": cycle_cutoff.isoformat().replace("+00:00", "Z")}).scalar()
        checkpoints.upsert_detector_checkpoint(db, detector_name=self.detector_name, source_table=self.source_table,
                                               last_processed_id=source_id, last_completed_window_end=cycle_cutoff,
                                               updated_at=cycle_cutoff)
        return DetectorRunResult(self.detector_name, self.source_table, cycle_range_start, cycle_cutoff, 1, 0,
                                 before["last_processed_id"], source_id, cycle_range_start, cycle_cutoff)


def test_paired_resume_catches_up_mqtt_trust_normally_then_processes_target(prepared):
    path, factory, operation = prepared
    with closing(sqlite3.connect(path)) as conn:
        messages(conn, 10, 20, malformed=True)
        messages(conn, 30, 20)
        conn.commit()
    target_packet = resume(path, operation)
    with factory.begin() as db:
        produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=40))
    ai = RecordingPacketIF()
    stages = (MqttFeatureRuleStage(), MqttMessageRuleStage(),
              PacketFeatureReadyStage(PacketRuleDetectorStage(capture_policy=CapturePolicy())), PacketFeatureReadyStage(ai))
    registry = StageRegistry(tuple(ConfiguredStage(stage.detector_name, stage, True) for stage in stages))
    first = run_orchestration_cycle(session_factory=factory, registry=registry)
    assert first.status == CYCLE_COMPLETED
    assert first.cutoff == BASE + timedelta(seconds=30)
    assert ai.calls == []
    with factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices")).scalar() == 77
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar() == 0
        assert checkpoints.get_detector_checkpoint(db, detector_name="mqtt_message_rule", source_table="mqtt_logs")["last_processed_id"] == 22
        assert checkpoints.get_detector_checkpoint(db, detector_name="packet_rule", source_table="packet_feature_logs")["last_processed_id"] == 1
    second = run_orchestration_cycle(session_factory=factory, registry=registry)
    assert second.status == CYCLE_COMPLETED
    assert ai.calls == [(BASE + timedelta(seconds=30), BASE + timedelta(seconds=40))]
    with factory() as db:
        assert db.execute(text("SELECT trust_score FROM devices")).scalar() == 57
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar() == 1
        assert checkpoints.get_detector_checkpoint(db, detector_name="packet_rule", source_table="packet_feature_logs")["last_processed_id"] == target_packet


def resume_with_empty_prefix(path, operation, *, raw_packet_count=16):
    target, boot = str(uuid4()), str(uuid4())
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        target_pk = insert(conn, "packet_capture_sessions", session_id=target, capture_interface="eth0",
                           started_at=utc(25), first_window_start=utc(30), status="RUNNING",
                           capture_gap_start=utc(10), capture_gap_end=utc(30))
        empty_ids = [insert(conn, "packet_capture_segments", capture_session_id=target_pk,
                            file_name=f"empty-{start}.pcap", capture_interface="eth0", window_start=utc(start),
                            window_end=utc(start + 10), status="EMPTY", packet_count=raw_packet_count,
                            start_delay_seconds=0, captured_duration_seconds=10)
                     for start in (30, 40)]
        traffic_id = packet(conn, target_pk, 50)
        conn.commit()
        plan = inspect_resume(conn, operation, target_session_id=target, current_boot_id=boot,
                              time_synchronized=True, now=BASE + timedelta(seconds=65))
        conn.execute("BEGIN IMMEDIATE")
        apply_resume(conn, plan, now=BASE + timedelta(seconds=65),
                     backup_path=str(path.with_suffix(".backup.db")), backup_sha256="a" * 64)
        conn.commit()
    return plan, empty_ids, traffic_id


def real_packet_if_with_normal_predictions():
    predicted_rows = []

    def predict_normal(_artifact, rows):
        predicted_rows.extend(rows)
        return [PacketIFPrediction("empty-prefix-test", 0.2, -0.2, 0.1, False, ()) for _ in rows]

    policy = CapturePolicy()
    artifact = PacketIFArtifact(
        model=None,  # type: ignore[arg-type] -- numerical inference is injected below.
        model_path=Path("unused-model.joblib"), metadata_path=Path("unused-metadata.json"),
        training_report_path=Path("unused-training.json"), model_version="empty-prefix-test", threshold=0.1,
        bundle_sha256="d" * 64, capture_policy=policy, metadata={},
    )
    return (PacketIsolationForestStage(artifact=artifact, expected_model_version="empty-prefix-test",
                                       capture_policy=policy, predict_rows=predict_normal), predicted_rows)


@pytest.mark.parametrize("raw_packet_count", [0, 16])
def test_empty_prefix_resume_pipeline_processes_from_first_boundary_and_preserves_isolation(prepared, raw_packet_count):
    path, factory, operation = prepared
    with closing(sqlite3.connect(path)) as conn:
        # Already isolated devices stay isolated. This test exercises DB state,
        # not the external iptables worker or hardware access-gap guarantees.
        insert(conn, "devices", device_id="esp32_02", ip_address="192.168.0.5", status="isolated", trust_score=20)
        insert_revision_raw(conn, device_id="esp32_02", registration_state="ACTIVE", effective_from=utc(-10))
        insert(conn, "firewall_rules", device_id="esp32_02", source_ip="192.168.0.5",
               status="APPLIED", reason="existing isolation")
        insert(conn, "isolation_history", device_id="esp32_02", action="ISOLATED", trust_score=20)
        messages(conn, 10, 3, malformed=True)
        messages(conn, 20, 3, malformed=True)
        for start in (30, 40, 50):
            messages(conn, start, 2)
        conn.commit()
        protected = {table: conn.execute(f"SELECT * FROM {table} ORDER BY id" if table != "devices"
                                         else "SELECT * FROM devices ORDER BY device_id").fetchall()
                     for table in ("devices", "device_policy_revisions", "firewall_rules", "isolation_history", "mqtt_logs")}
        cp_before = conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name").fetchall()
    plan, empty_ids, traffic_id = resume_with_empty_prefix(path, operation, raw_packet_count=raw_packet_count)
    assert plan["maintenance_end"] == utc(30)
    assert plan["first_target_evidence"]["segment"]["window_start"] == utc(50)
    with factory() as db:
        for name, source, last_id, boundary, updated in cp_before:
            row = checkpoints.get_detector_checkpoint(db, detector_name=name, source_table=source)
            assert row["last_processed_id"] == last_id
            assert row["last_completed_window_end"] == utc(30 if name in ("packet_rule", "packet_if") else 10)
        windows = dataset_maintenance_windows(db)
        assert windows == ((BASE + timedelta(seconds=10), BASE + timedelta(seconds=30)),)
        assert not overlaps_maintenance(windows, BASE + timedelta(seconds=30), BASE + timedelta(seconds=40))
    with factory.begin() as db:
        producer = produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=40))
        assert producer.created_feature_count == 1
        assert db.execute(text("SELECT window_start FROM feature_logs ORDER BY id")).scalars().all() == [utc(0), utc(30)]
    ai, predicted_rows = real_packet_if_with_normal_predictions()
    stages = (MqttFeatureRuleStage(), MqttMessageRuleStage(),
              PacketFeatureReadyStage(PacketRuleDetectorStage(capture_policy=CapturePolicy())), PacketFeatureReadyStage(ai))
    registry = StageRegistry(tuple(ConfiguredStage(stage.detector_name, stage, True) for stage in stages))
    catchup = run_orchestration_cycle(session_factory=factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED and catchup.cutoff == BASE + timedelta(seconds=30)
    assert predicted_rows == []
    empty_window = run_orchestration_cycle(session_factory=factory, registry=registry)
    assert empty_window.status == CYCLE_COMPLETED
    assert empty_window.range_start == BASE + timedelta(seconds=30)
    assert empty_window.cutoff == BASE + timedelta(seconds=40)
    assert predicted_rows == []
    with factory() as db:
        for name in ("packet_rule", "packet_if"):
            cp = checkpoints.get_detector_checkpoint(db, detector_name=name, source_table="packet_feature_logs")
            assert cp["last_processed_id"] == 1  # EMPTY cannot erase or jump the real source ID.
            assert cp["last_completed_window_end"] == utc(40)
    with factory.begin() as db:
        producer = produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=60))
        assert producer.created_feature_count == 2
        assert db.execute(text("SELECT window_start FROM feature_logs ORDER BY id")).scalars().all() == [utc(0), utc(30), utc(40), utc(50)]
    processing = run_orchestration_cycle(session_factory=factory, registry=registry)
    assert processing.status == CYCLE_COMPLETED
    assert processing.range_start == BASE + timedelta(seconds=40)
    assert processing.cutoff == BASE + timedelta(seconds=60)
    assert len(predicted_rows) == 1 and predicted_rows[0]["packet_count"] == 2
    with factory() as db:
        for name, source in REQUIRED_CHECKPOINTS:
            cp = checkpoints.get_detector_checkpoint(db, detector_name=name, source_table=source)
            assert cp["last_completed_window_end"] == utc(60)
            if name in ("packet_rule", "packet_if"):
                assert cp["last_processed_id"] == traffic_id
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar() == 0
        assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar() == 0
        for segment in empty_ids:
            row = db.execute(text("SELECT status,packet_count FROM packet_capture_segments WHERE id=:id"), {"id": segment}).one()
            assert tuple(row) == ("EMPTY", raw_packet_count)
            assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs WHERE capture_segment_id=:id"), {"id": segment}).scalar() == 0
    with closing(sqlite3.connect(path)) as conn:
        after = {table: conn.execute(f"SELECT * FROM {table} ORDER BY id" if table != "devices"
                                    else "SELECT * FROM devices ORDER BY device_id").fetchall()
                 for table in protected}
        assert after == protected


def test_changed_committed_empty_prefix_holds_producer_before_consuming_mqtt(prepared):
    path, factory, operation = prepared
    plan, empty_ids, _ = resume_with_empty_prefix(path, operation)
    with closing(sqlite3.connect(path)) as conn:
        messages(conn, 30)
        insert(conn, "packet_feature_logs", capture_segment_id=empty_ids[0], device_id="esp32_01",
               peer_ip="192.168.0.4", direction="INBOUND", window_start=utc(30), window_end=utc(40),
               packet_count=2, total_bytes=100, avg_packet_size=50, max_packet_size=50)
        conn.commit()
        before = conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name").fetchall()
        raw = conn.execute("SELECT * FROM mqtt_logs ORDER BY id").fetchall()
    with pytest.raises(PlannedMaintenanceError, match="EMPTY prefix"):
        with factory.begin() as db:
            produce_mqtt_features_until(db, producer_cutoff=BASE + timedelta(seconds=60))
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("SELECT * FROM detector_checkpoints ORDER BY detector_name").fetchall() == before
        assert conn.execute("SELECT * FROM mqtt_logs ORDER BY id").fetchall() == raw
        assert conn.execute("SELECT COUNT(*) FROM feature_logs").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM planned_maintenance_resumes WHERE operation_id=?", (plan["operation_id"],)).fetchone()[0] == 1


def test_candidate_qc_holds_on_maintenance_overlap_without_mutating_snapshot(package, monkeypatch):
    from tests.test_normal_collection_export import START, digest

    before = digest(package / "after.db")
    monkeypatch.setattr("ai.export_normal_collection.dataset_maintenance_windows",
                        lambda _db: ((START + timedelta(seconds=10), START + timedelta(seconds=20)),))
    report = export_normal_collection(package)
    assert report["status"] == "HOLD"
    assert "maintenance:approved_maintenance_interval_overlap" in report["hold_reasons"]
    assert report["training_approved"] is False
    assert digest(package / "after.db") == before
