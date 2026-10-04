"""Approved single-window Packet gaps remain explicit in runtime readiness."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai.predict_packet_isolation_forest import PacketIFArtifact, PacketIFPrediction
from backend.app.config import Settings
from db.migration_runner import apply_migrations
from edge.detection import runtime_checkpoint_repository as checkpoints
from edge.detection.packet_ai_detector import PacketIsolationForestStage
from edge.detection.phase4_time import format_db_utc
from edge.features.run_mqtt_feature_builder import bootstrap_producer_checkpoint, run_producer_cycle
from edge.orchestration.packet_stage_readiness import (
    PacketFeatureRangeNotReadyError,
    PacketFeatureReadyStage,
    require_packet_feature_ready_range,
)
from edge.orchestration.run_detection_orchestrator import (
    CYCLE_COMPLETED,
    CYCLE_SKIPPED_NO_NEW_WINDOW,
    run_orchestration_cycle,
)
from edge.orchestration.stage_registry import (
    ConfiguredStage,
    MQTT_FEATURE_RULE,
    MQTT_MESSAGE_RULE,
    PACKET_IF,
    PACKET_RULE,
    StageRegistry,
    build_stage_registry,
)
from edge.packet import capture_session_repository as capture_sessions
from edge.packet.capture_policy import CapturePolicy
from edge.packet.pcap_naming import build_pcap_filename
from edge.packet.segment_gap_recovery import apply_segment_gap_plan, build_segment_gap_plan
from edge.trust.trust_score_v2 import TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE


BASE = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)
CAPTURE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
DEVICE_ID = "gap-runtime-device"
DEVICE_IP = "192.0.2.4"


def _time(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


@pytest.fixture
def runtime(tmp_path: Path):
    db_path = tmp_path / "segment-gap.db"
    apply_migrations(db_path)
    engine = create_engine(f"sqlite:///{db_path}")
    session_factory = sessionmaker(bind=engine)
    with session_factory() as db:
        db.execute(text("INSERT INTO devices (device_id, ip_address, status, trust_score) "
                        "VALUES (:device, :ip, 'normal', 100)"),
                   {"device": DEVICE_ID, "ip": DEVICE_IP})
        db.execute(text("""
            INSERT INTO device_policy_revisions (
                device_id, revision, effective_from, registration_state, policy_profile,
                expected_publish_interval_seconds, publish_count_max, payload_size_max_bytes,
                packet_rate_max_pps, byte_rate_max_bytes_per_second, created_at, created_by, reason
            ) VALUES (:device, 1, :start, 'ACTIVE', 'periodic-sensor-v1',
                      10, 15, 1024, 10.0, 2500.0, :start, 'test', 'normal test policy')
        """), {"device": DEVICE_ID, "start": format_db_utc(BASE)})
        session_pk = capture_sessions.create_session(
            db, session_id=CAPTURE_ID, capture_interface="eth0", started_at=BASE,
        )
        capture_sessions.set_first_window_start(db, session_pk, BASE)
        bootstrap_producer_checkpoint(db, now=BASE)
        db.commit()
    try:
        yield session_factory, db_path, session_pk
    finally:
        engine.dispose()


def _feature(db, segment_id: int, seconds: int) -> int:
    result = db.execute(text("""
        INSERT INTO packet_feature_logs (
            capture_segment_id, device_id, peer_ip, direction,
            window_start, window_end, packet_count, total_bytes,
            avg_packet_size, max_packet_size, mean_inter_arrival_time,
            distinct_dest_port_count, tcp_syn_count, mqtt_related_packet_count,
            non_mqtt_tcp_udp_packet_count, capture_scope
        ) VALUES (
            :segment, :device, :ip, 'INBOUND', :start, :end,
            2, 20, 10.0, 10, 0.01, 1, 0, 2, 0, 'gateway'
        )
    """), {"segment": segment_id, "device": DEVICE_ID, "ip": DEVICE_IP,
             "start": format_db_utc(_time(seconds)), "end": format_db_utc(_time(seconds + 10))})
    return int(result.lastrowid)


def _segment(db, session_pk: int, seconds: int, *, status: str = "PROCESSED",
             interface: str = "eth0") -> tuple[int, int | None]:
    start, end = _time(seconds), _time(seconds + 10)
    kwargs = dict(
        capture_session_pk=session_pk,
        file_name=build_pcap_filename(session_id=CAPTURE_ID, interface=interface,
                                      window_start=start, window_end=end, tmp=False),
        capture_interface=interface, window_start=start, window_end=end,
        actual_capture_started_at=start + timedelta(milliseconds=200),
        capture_stop_requested_at=end,
        capture_process_exited_at=end + timedelta(milliseconds=50),
        start_delay_seconds=0.2, captured_duration_seconds=9.8,
    )
    if status == "FAILED":
        kwargs["captured_duration_seconds"] = 2.0
        segment_id = capture_sessions.insert_failed_segment(
            db, **kwargs, error_code="PARTIAL_CAPTURE", error_message="preserved partial capture",
        )
        return segment_id, None
    segment_id = capture_sessions.insert_ready_segment(db, **kwargs)
    feature_id = _feature(db, segment_id, seconds) if status == "PROCESSED" else None
    db.execute(text("UPDATE packet_capture_segments SET status = :status, packet_count = :count, "
                    "processed_at = :end WHERE id = :id"),
               {"status": status, "count": 2 if feature_id else 0,
                "end": format_db_utc(end), "id": segment_id})
    return segment_id, feature_id


def _registry(tmp_path: Path) -> StageRegistry:
    built = build_stage_registry(
        enabled=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE, PACKET_RULE],
        required=[MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE, PACKET_RULE],
        app_settings=Settings(_env_file=None),
    )
    policy = CapturePolicy()
    version = "segment-gap-test-v1"
    artifact = PacketIFArtifact(
        model=object(), model_path=tmp_path / "model.joblib",
        metadata_path=tmp_path / "metadata.json", training_report_path=tmp_path / "report.json",
        model_version=version, threshold=0.1, bundle_sha256="d" * 64,
        capture_policy=policy, metadata={},
    )

    def predict_normal(_artifact, rows):
        return tuple(PacketIFPrediction(
            model_version=version, raw_decision_score=0.2, anomaly_score=-0.2,
            threshold=0.1, is_anomaly=False,
            feature_values=tuple(float(row[name]) for name in (
                "packet_count", "total_bytes", "avg_packet_size", "max_packet_size",
                "mean_inter_arrival_time", "distinct_dest_port_count",
            )),
        ) for row in rows)

    packet_if = PacketFeatureReadyStage(PacketIsolationForestStage(
        artifact=artifact, expected_model_version=version, capture_policy=policy,
        predict_rows=predict_normal,
    ))
    return StageRegistry(built.stages + (ConfiguredStage(PACKET_IF, packet_if, True),))


def _seed(runtime, tmp_path: Path, *, second_failure: bool = False):
    session_factory, db_path, session_pk = runtime
    registry = _registry(tmp_path)
    with session_factory() as db:
        _, first_feature = _segment(db, session_pk, 0)
        failed_segment, _ = _segment(db, session_pk, 10, status="FAILED")
        _, tail_feature = _segment(db, session_pk, 20)
        if second_failure:
            _segment(db, session_pk, 30, status="FAILED")
        for seconds in range(0, 40 if second_failure else 30, 10):
            db.execute(text("""
                INSERT INTO mqtt_logs (
                    device_id, topic, payload, payload_size, received_at,
                    is_json_valid, is_topic_valid
                ) VALUES (:device, :topic, '{}', 2, :received, 1, 1)
            """), {"device": DEVICE_ID, "topic": f"iot/{DEVICE_ID}/sensor",
                     "received": format_db_utc(_time(seconds + 1))})
        db.commit()
    run_producer_cycle(session_factory=session_factory,
                       now=_time(41 if second_failure else 31))
    initial = run_orchestration_cycle(session_factory=session_factory, registry=registry)
    assert initial.status == CYCLE_COMPLETED
    assert initial.cutoff == _time(10)
    return registry, failed_segment, first_feature, tail_feature


def _readiness(session_factory):
    with session_factory() as db:
        return capture_sessions.get_packet_feature_ready_through(db, session_id=CAPTURE_ID)


def _checkpoint(db, detector_name: str, source_table: str = "packet_feature_logs"):
    return checkpoints.get_detector_checkpoint(db, detector_name=detector_name, source_table=source_table)


def _approve(runtime, failed_segment: int, tmp_path: Path):
    _, db_path, _ = runtime
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        failed = connection.execute("SELECT * FROM packet_capture_segments WHERE id = ?",
                                    (failed_segment,)).fetchone()
        plan = build_segment_gap_plan(
            connection, capture_session_id=CAPTURE_ID, failed_segment_id=failed_segment,
            approved_by="woomin", reason="Explicitly approved single partial capture window",
            repository_commit="a" * 40, database_path=str(db_path.resolve()),
            backup_path=str((tmp_path / "backup.db").resolve()),
            preserved_pcap_path=str((tmp_path / failed["file_name"]).resolve()),
            pcap_sha256="b" * 64,
        )
        connection.execute("BEGIN IMMEDIATE")
        apply_segment_gap_plan(connection, plan, backup_sha256="c" * 64)
        connection.commit()
    return plan


def test_approved_gap_catches_up_mqtt_trust_then_consumes_existing_healthy_tail(runtime, tmp_path: Path):
    session_factory, _, _ = runtime
    registry, failed_segment, first_feature, tail_feature = _seed(runtime, tmp_path)
    with session_factory() as db:
        failed_before = dict(db.execute(text("SELECT * FROM packet_capture_segments WHERE id = :id"),
                                        {"id": failed_segment}).mappings().one())
    _approve(runtime, failed_segment, tmp_path)
    assert _readiness(session_factory).packet_feature_ready_through == _time(30)

    catchup = run_orchestration_cycle(session_factory=session_factory, registry=registry)
    assert catchup.status == CYCLE_COMPLETED
    assert (catchup.range_start, catchup.cutoff) == (_time(10), _time(20))
    assert {result.detector_name for result in catchup.stage_results} == {
        MQTT_FEATURE_RULE, MQTT_MESSAGE_RULE,
    }
    with session_factory() as db:
        for detector in (PACKET_RULE, PACKET_IF):
            checkpoint = _checkpoint(db, detector)
            assert checkpoint["last_processed_id"] == first_feature
            assert checkpoint["last_completed_window_end"] == format_db_utc(_time(20))
        for detector, source in ((MQTT_FEATURE_RULE, "feature_logs"),
                                 (MQTT_MESSAGE_RULE, "mqtt_logs"),
                                 (TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)):
            assert _checkpoint(db, detector, source)["last_completed_window_end"] == format_db_utc(_time(20))

    resumed = run_orchestration_cycle(session_factory=session_factory, registry=registry)
    assert resumed.status == CYCLE_COMPLETED
    assert (resumed.range_start, resumed.cutoff) == (_time(20), _time(30))
    packet_results = [result for result in resumed.stage_results
                      if result.detector_name in (PACKET_RULE, PACKET_IF)]
    assert len(packet_results) == 2
    assert all(result.selected_count == 1 and result.capture_session_id == CAPTURE_ID
               for result in packet_results)
    with session_factory() as db:
        for detector in (PACKET_RULE, PACKET_IF):
            checkpoint = _checkpoint(db, detector)
            assert checkpoint["last_processed_id"] == tail_feature
            assert checkpoint["last_completed_window_end"] == format_db_utc(_time(30))
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)[
            "last_completed_window_end"] == format_db_utc(_time(30))
        failed_after = dict(db.execute(text("SELECT * FROM packet_capture_segments WHERE id = :id"),
                                       {"id": failed_segment}).mappings().one())
        assert failed_after == failed_before
        assert db.execute(text("SELECT COUNT(*) FROM packet_feature_logs")).scalar_one() == 2
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one() == 0
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 100
        assert db.execute(text("SELECT COUNT(*) FROM packet_segment_gap_recoveries")).scalar_one() == 1
    assert run_orchestration_cycle(session_factory=session_factory, registry=registry).status == CYCLE_SKIPPED_NO_NEW_WINDOW


def test_second_unaudited_failure_stops_after_first_gap_healthy_tail(runtime, tmp_path: Path):
    session_factory, _, _ = runtime
    registry, failed_segment, _, tail_feature = _seed(runtime, tmp_path, second_failure=True)
    _approve(runtime, failed_segment, tmp_path)
    assert _readiness(session_factory).packet_feature_ready_through == _time(30)
    assert run_orchestration_cycle(session_factory=session_factory, registry=registry).cutoff == _time(20)
    assert run_orchestration_cycle(session_factory=session_factory, registry=registry).cutoff == _time(30)
    assert run_orchestration_cycle(session_factory=session_factory, registry=registry).status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with session_factory() as db:
        for detector in (PACKET_RULE, PACKET_IF):
            checkpoint = _checkpoint(db, detector)
            assert checkpoint["last_processed_id"] == tail_feature
            assert checkpoint["last_completed_window_end"] == format_db_utc(_time(30))
        assert db.execute(text("SELECT COUNT(*) FROM packet_segment_gap_recoveries")).scalar_one() == 1


@pytest.mark.parametrize("tamper", ["plan_json", "audit_sha", "failed_snapshot", "failed_feature", "overlap_segment", "checkpoint_id"])
def test_changed_audit_or_failed_evidence_cannot_catch_up_or_release_tail(runtime, tmp_path: Path, tamper: str):
    session_factory, _, session_pk = runtime
    registry, failed_segment, _, _ = _seed(runtime, tmp_path)
    _approve(runtime, failed_segment, tmp_path)
    with session_factory() as db:
        if tamper == "plan_json":
            plan = json.loads(db.execute(text("SELECT plan_json FROM packet_segment_gap_recoveries")).scalar_one())
            plan["reason"] = "changed without renewing approval"
            db.execute(text("UPDATE packet_segment_gap_recoveries SET plan_json = :plan"),
                       {"plan": json.dumps(plan)})
        elif tamper == "audit_sha":
            db.execute(text("UPDATE packet_segment_gap_recoveries SET plan_sha256 = :sha"), {"sha": "f" * 64})
        elif tamper == "failed_snapshot":
            db.execute(text("UPDATE packet_capture_segments SET error_message = 'changed evidence' WHERE id = :id"),
                       {"id": failed_segment})
        elif tamper == "failed_feature":
            _feature(db, failed_segment, 10)
        elif tamper == "overlap_segment":
            _segment(db, session_pk, 10, status="EMPTY", interface="eth1")
        else:
            db.execute(text("UPDATE detector_checkpoints SET last_processed_id = last_processed_id + 100 "
                            "WHERE detector_name = 'packet_if'"))
        db.commit()
    outcome = run_orchestration_cycle(session_factory=session_factory, registry=registry)
    # The invalid catch-up leaves MQTT and Trust at the last healthy boundary.
    assert outcome.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with session_factory() as db:
        for detector, source in ((MQTT_FEATURE_RULE, "feature_logs"),
                                 (MQTT_MESSAGE_RULE, "mqtt_logs"),
                                 (TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)):
            assert _checkpoint(db, detector, source)["last_completed_window_end"] == format_db_utc(_time(10))


def test_missing_008_retains_failure_barrier(runtime, tmp_path: Path):
    session_factory, _, _ = runtime
    registry, _, _, _ = _seed(runtime, tmp_path)
    with session_factory() as db:
        db.execute(text("DROP TABLE packet_segment_gap_recoveries"))
        db.execute(text("DELETE FROM schema_migrations WHERE version = 8"))
        db.commit()
    assert _readiness(session_factory).packet_feature_ready_through == _time(10)
    assert run_orchestration_cycle(session_factory=session_factory, registry=registry).status == CYCLE_SKIPPED_NO_NEW_WINDOW


def test_unaudited_failed_window_keeps_packet_mqtt_and_trust_before_gap(runtime, tmp_path: Path):
    session_factory, _, _ = runtime
    registry, failed_segment, first_feature, _ = _seed(runtime, tmp_path)
    assert _readiness(session_factory).packet_feature_ready_through == _time(10)
    outcome = run_orchestration_cycle(session_factory=session_factory, registry=registry)
    assert outcome.status == CYCLE_SKIPPED_NO_NEW_WINDOW
    with session_factory() as db:
        for detector in (PACKET_RULE, PACKET_IF):
            checkpoint = _checkpoint(db, detector)
            assert checkpoint["last_processed_id"] == first_feature
            assert checkpoint["last_completed_window_end"] == format_db_utc(_time(10))
        assert _checkpoint(db, TRUST_DETECTOR_NAME, TRUST_SOURCE_TABLE)[
            "last_completed_window_end"] == format_db_utc(_time(10))
        assert db.execute(text("SELECT status FROM packet_capture_segments WHERE id = :id"),
                          {"id": failed_segment}).scalar_one() == "FAILED"


@pytest.mark.parametrize("status", ["READY", "EMPTY"])
def test_gate_rejects_features_on_non_processed_segments(runtime, status: str):
    session_factory, _, session_pk = runtime
    with session_factory() as db:
        segment_id, _ = _segment(db, session_pk, 0, status=status)
        _feature(db, segment_id, 0)
        db.commit()
        with pytest.raises(PacketFeatureRangeNotReadyError):
            require_packet_feature_ready_range(db, cycle_range_start=BASE, cycle_cutoff=_time(10))


@pytest.mark.parametrize("overlap_start", [0, 5])
def test_duplicate_or_overlapping_segment_cannot_extend_ready_prefix(runtime, overlap_start: int):
    session_factory, _, session_pk = runtime
    with session_factory() as db:
        _segment(db, session_pk, 0)
        _segment(db, session_pk, overlap_start, status="EMPTY", interface="eth1")
        db.commit()
        readiness = capture_sessions.get_packet_feature_ready_through(db, session_id=CAPTURE_ID)
        assert readiness.packet_feature_ready_through is None
        with pytest.raises(PacketFeatureRangeNotReadyError):
            require_packet_feature_ready_range(db, cycle_range_start=BASE, cycle_cutoff=_time(10))


def test_feature_window_must_match_capture_window_before_packet_stage_runs(runtime):
    session_factory, _, session_pk = runtime
    with session_factory() as db:
        segment_id, feature_id = _segment(db, session_pk, 0)
        db.execute(text("UPDATE packet_feature_logs SET window_start = :start, window_end = :end "
                        "WHERE id = :id"),
                   {"start": format_db_utc(_time(10)), "end": format_db_utc(_time(20)), "id": feature_id})
        db.commit()
        with pytest.raises(PacketFeatureRangeNotReadyError):
            require_packet_feature_ready_range(db, cycle_range_start=BASE, cycle_cutoff=_time(10))
