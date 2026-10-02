from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
import json

from edge.detection.mqtt_adapters import (
    MqttFeatureRuleStage,
    MqttIsolationForestStage,
    MqttMessageRuleStage,
)
from edge.features.collect_feature_logs import produce_mqtt_features_until
from edge.mqtt.subscriber import build_mqtt_log_row, insert_mqtt_log
from edge.trust.trust_score_v2 import apply_trust_score_v2_until


T0 = datetime(2026, 9, 30, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 9, 30, 0, 0, 10, tzinfo=timezone.utc)
T2 = datetime(2026, 9, 30, 0, 0, 20, tzinfo=timezone.utc)
START = "2026-09-30T00:00:00Z"
END = "2026-09-30T00:00:10Z"


@pytest.fixture
def session_factory(tmp_path: Path):
    path = tmp_path / "phase8-trust.db"
    apply_migrations(path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autoflush=False)
    try:
        yield factory
    finally:
        engine.dispose()


def _revision(db, *, device_id="esp32_01", revision=1, status="ACTIVE",
              effective=START, created=START, publish=15, payload=5120,
              packets=10.0, bytes_=2500.0):
    db.execute(text("""INSERT INTO device_policy_revisions (
        device_id, revision, effective_from, registration_state,
        policy_profile, expected_publish_interval_seconds,
        publish_count_max, payload_size_max_bytes, packet_rate_max_pps,
        byte_rate_max_bytes_per_second, created_at, created_by, reason
    ) VALUES (
        :device_id, :revision, :effective, :status, 'periodic-sensor-v1', 5,
        :publish, :payload, :packets, :bytes_, :created, 'test', 'test setup'
    )"""), locals())


def _seed(db, *, status: str, with_policy: bool = True,
          publish: int = 15, payload: int = 5120):
    db.execute(text("""INSERT INTO devices (
        device_id, ip_address, status, trust_score, registration_effective_from
    ) VALUES ('esp32_01', '192.0.2.1', 'normal', 40, :start)"""),
        {"start": START})
    if with_policy:
        _revision(db, status=status, publish=publish, payload=payload)


def _event(db, event_type: str = "DEVICE_ID_MISMATCH") -> int:
    result = db.execute(text("""INSERT INTO detection_events (
        device_id, detector_type, event_type, severity, score_delta,
        analysis_window_start, analysis_window_end, incident_family, detected_at
    ) VALUES ('esp32_01', 'RULE', :event_type, 'high', -25,
              :start, :end, 'IDENTITY', :end)"""),
        {"event_type": event_type, "start": START, "end": END})
    return int(result.lastrowid)


def _run(factory, *, decision_at=T2):
    with factory() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db, cycle_range_start=T0, cycle_cutoff=T1,
                decision_at=decision_at,
            )
        score = db.execute(text("SELECT trust_score FROM devices")).scalar_one()
        events = db.execute(text("""SELECT event_type, score_delta,
            applied_to_score, processing_reason, processed_at
            FROM detection_events ORDER BY id""")).mappings().all()
        history = db.execute(text("SELECT COUNT(*) FROM trust_score_history")).scalar_one()
        firewall = db.execute(text("SELECT COUNT(*) FROM firewall_rules")).scalar_one()
        checkpoint = db.execute(text("""SELECT last_completed_window_end
            FROM detector_checkpoints WHERE detector_name='trust_score_v2'""")).scalar_one()
        return result, score, events, history, firewall, checkpoint


def test_pending_predictor_receives_feature_and_event_is_recorded_without_response(
    session_factory, monkeypatch,
):
    seen = []
    def predict(row, _model_path):
        seen.append(dict(row))
        return {"is_anomaly": True, "prediction": -1,
                "anomaly_score": -0.9, "event_type": "AI_ANOMALY"}
    monkeypatch.setattr("edge.detection.mqtt_adapters.predict_feature_window", predict)
    with session_factory() as db:
        _seed(db, status="PENDING")
        db.execute(text("""INSERT INTO feature_logs
            (device_id, window_start, window_end, publish_count,
             max_payload_size) VALUES ('esp32_01', :start, :end, 3, 100)"""),
            {"start": START, "end": END})
        db.commit()
    with session_factory() as db:
        with db.begin():
            stage = MqttIsolationForestStage(model_path=Path("unused.joblib"))
            detection = stage.run_until(db, cycle_range_start=T0, cycle_cutoff=T1)
        assert detection.created_event_count == 1
    result, score, events, history, firewall, checkpoint = _run(session_factory)
    assert len(seen) == 1 and seen[0]["device_id"] == "esp32_01"
    assert result.processed_event_count == 1
    assert (score, history, firewall) == (40, 0, 0)
    assert events[0]["event_type"] == "AI_ANOMALY"
    assert events[0]["score_delta"] == -15
    assert events[0]["applied_to_score"] == 0
    assert events[0]["processing_reason"] == "PENDING_AT_WINDOW"
    assert events[0]["processed_at"] is not None
    assert checkpoint == END
    assert _run(session_factory)[0].processed_event_count == 0


def test_pending_window_is_not_scored_after_activation(session_factory):
    with session_factory() as db:
        _seed(db, status="PENDING")
        _event(db)
        _revision(db, revision=2, status="ACTIVE", effective=END, created=END)
        db.commit()
    _, score, events, history, firewall, _ = _run(session_factory)
    assert (score, history, firewall) == (40, 0, 0)
    assert events[0]["processing_reason"] == "PENDING_AT_WINDOW"


def test_late_pending_window_keeps_pending_exclusion_reason(session_factory):
    with session_factory() as db:
        _seed(db, status="PENDING")
        _event(db)
        _revision(db, revision=2, status="ACTIVE", effective=END, created=END)
        db.commit()
    with session_factory() as db:
        with db.begin():
            result = apply_trust_score_v2_until(
                db, cycle_range_start=T1, cycle_cutoff=T2,
                decision_at=T2,
            )
        assert result.processed_event_count == 1
        assert db.execute(text("SELECT trust_score FROM devices")).scalar_one() == 40
        event = db.execute(text("""SELECT processing_reason, applied_to_score,
            processed_at FROM detection_events""")).mappings().one()
        assert event["processing_reason"] == "PENDING_AT_WINDOW"
        assert event["applied_to_score"] == 0
        assert event["processed_at"] is not None


def test_scheduled_disable_blocks_old_active_window_before_effective_time(
    session_factory,
):
    with session_factory() as db:
        _seed(db, status="ACTIVE")
        _event(db)
        _revision(db, revision=2, status="DISABLED",
                  effective="2026-09-30T00:00:30Z",
                  created="2026-09-30T00:00:05Z")
        db.commit()
    _, score, events, history, firewall, _ = _run(
        session_factory, decision_at=T1
    )
    assert (score, history, firewall) == (40, 0, 0)
    assert events[0]["processing_reason"] == "DISABLE_REQUESTED_OR_DISABLED"
    assert events[0]["processed_at"] is not None


def test_active_policy_gap_is_processed_without_penalty(session_factory):
    with session_factory() as db:
        _seed(db, status="ACTIVE", with_policy=False)
        _event(db)
        db.commit()
    _, score, events, history, firewall, checkpoint = _run(session_factory)
    assert (score, history, firewall) == (40, 0, 0)
    assert events[0]["processing_reason"] == "POLICY_UNAVAILABLE"
    assert events[0]["processed_at"] is not None
    assert checkpoint == END


def test_invalid_policy_revision_is_rejected_by_migration(session_factory):
    with session_factory() as db:
        _seed(db, status="ACTIVE", with_policy=False)
        with pytest.raises(IntegrityError):
            _revision(db, revision=0)
        db.rollback()
        assert db.execute(text("SELECT COUNT(*) FROM device_policy_revisions")).scalar_one() == 0


def test_policy_gap_keeps_malformed_detection_without_threshold_fallback(
    session_factory,
):
    with session_factory() as db:
        _seed(db, status="ACTIVE", with_policy=False)
        db.execute(text("""INSERT INTO feature_logs (
            device_id, window_start, window_end, publish_count,
            max_payload_size, malformed_payload_count
        ) VALUES ('esp32_01', :start, :end, 100, 10000, 3)"""),
        {"start": START, "end": END})
        db.commit()
    with session_factory() as db:
        with db.begin():
            detected = MqttFeatureRuleStage().run_until(
                db, cycle_range_start=T0, cycle_cutoff=T1
            )
        assert detected.created_event_count == 2
    _, score, events, history, firewall, _ = _run(session_factory)
    assert {event["event_type"] for event in events} == {
        "POLICY_UNAVAILABLE", "MALFORMED_PAYLOAD",
    }
    assert all(event["processing_reason"] == "POLICY_UNAVAILABLE" for event in events)
    assert all(event["applied_to_score"] == 0 for event in events)
    assert (score, history, firewall) == (40, 0, 0)


def test_mqtt_feature_stage_uses_device_revision_and_does_not_reopen_old_window(
    session_factory,
):
    with session_factory() as db:
        _seed(db, status="ACTIVE", publish=10, payload=100)
        db.execute(text("""INSERT INTO devices (device_id, ip_address)
            VALUES ('esp32_02', '192.0.2.2')"""))
        db.execute(text("""UPDATE devices SET registration_effective_from=:start
            WHERE device_id='esp32_02'"""),
            {"start": START})
        _revision(db, device_id="esp32_02", status="ACTIVE",
                  publish=20, payload=200, bytes_=1000)
        _revision(db, revision=2, status="ACTIVE", effective=END,
                  created=END, publish=50, payload=500,
                  packets=50, bytes_=5000)
        for device_id in ("esp32_01", "esp32_02"):
            db.execute(text("""INSERT INTO feature_logs
                (device_id, window_start, window_end, publish_count,
                 max_payload_size) VALUES
                (:device_id, :start, :end, 11, 101)"""),
                {"device_id": device_id, "start": START, "end": END})
        db.commit()
    with session_factory() as db:
        with db.begin():
            result = MqttFeatureRuleStage().run_until(
                db, cycle_range_start=T0, cycle_cutoff=T1
            )
        assert result.created_event_count == 2
        rows = db.execute(text("""SELECT device_id, event_type, policy_version,
            evidence_json FROM detection_events ORDER BY id""")).mappings().all()
        assert {(row["device_id"], row["event_type"]) for row in rows} == {
            ("esp32_01", "ABNORMAL_PUBLISH_RATE"),
            ("esp32_01", "LARGE_PAYLOAD"),
        }
        evidence = {row["event_type"]: json.loads(row["evidence_json"]) for row in rows}
        assert evidence["ABNORMAL_PUBLISH_RATE"]["device_policy_revision"] == 1
        assert evidence["ABNORMAL_PUBLISH_RATE"]["threshold"] == 10
        assert evidence["ABNORMAL_PUBLISH_RATE"]["unit"] == "messages/10s"
        assert evidence["LARGE_PAYLOAD"]["threshold"] == 100
        assert evidence["LARGE_PAYLOAD"]["unit"] == "bytes"
        assert all(row["policy_version"] == "mqtt-feature-rule-v1" for row in rows)
        db.rollback()
        with db.begin():
            repeated = MqttFeatureRuleStage().run_until(
                db, cycle_range_start=T0, cycle_cutoff=T1
            )
        assert repeated.created_event_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 2


def test_delayed_mqtt_identity_keeps_unknown_when_payload_registered_later(
    session_factory,
):
    with session_factory() as db:
        _seed(db, status="ACTIVE")
        db.execute(text("""INSERT INTO devices (
            device_id, ip_address, registration_effective_from
        ) VALUES ('esp32_02', '192.0.2.2', :next)"""),
            {"next": END})
        _revision(db, device_id="esp32_02", status="PENDING",
                  effective=END, created=END)
        db.execute(text("""INSERT INTO mqtt_logs
            (device_id, topic, payload, received_at, is_json_valid)
            VALUES ('esp32_01', 'iot/esp32_01/sensor',
                    '{"device_id":"esp32_02"}', '2026-09-30T00:00:04Z', 1)"""))
        db.commit()
    with session_factory() as db:
        with db.begin():
            result = MqttMessageRuleStage().run_until(
                db, cycle_range_start=T0, cycle_cutoff=T1
            )
        assert result.created_event_count == 1
        row = db.execute(text("""SELECT device_id, event_type, evidence_json,
            analysis_window_start FROM detection_events""")).mappings().one()
        assert row["device_id"] == "esp32_02"
        assert row["event_type"] == "UNKNOWN_DEVICE"
        assert row["analysis_window_start"] == START
        assert json.loads(row["evidence_json"])["candidate_device_id"] == "esp32_01"


def test_pending_raw_keeps_precise_receive_time_updates_seen_and_builds_feature(
    session_factory,
):
    received = datetime(2026, 9, 30, 0, 0, 4, 123456, tzinfo=timezone.utc)
    with session_factory() as db:
        _seed(db, status="PENDING")
        db.commit()
    with session_factory() as db:
        row = build_mqtt_log_row(
            "iot/esp32_01/sensor", '{"device_id":"esp32_01"}', received
        )
        assert row["received_at"] == "2026-09-30T00:00:04.123456Z"
        insert_mqtt_log(db, row)
        assert db.execute(text("SELECT received_at FROM mqtt_logs")).scalar_one() == row["received_at"]
        assert db.execute(text("SELECT last_seen_at FROM devices")).scalar_one() == row["received_at"]
        earlier = build_mqtt_log_row(
            "iot/esp32_01/sensor", '{"device_id":"esp32_01"}',
            datetime(2026, 9, 30, 0, 0, 3, 999999, tzinfo=timezone.utc),
        )
        insert_mqtt_log(db, earlier)
        assert db.execute(text("SELECT last_seen_at FROM devices")).scalar_one() == row["received_at"]
        db.rollback()
        with db.begin():
            produced = produce_mqtt_features_until(db, producer_cutoff=T1)
        assert produced.created_feature_count == 1
        feature = db.execute(text("""SELECT device_id, window_start, publish_count
            FROM feature_logs""")).mappings().one()
        assert (feature["device_id"], feature["window_start"], feature["publish_count"]) == (
            "esp32_01", START, 2
        )


def test_disabled_raw_records_communication_without_new_feature(session_factory):
    with session_factory() as db:
        _seed(db, status="DISABLED")
        db.commit()
    with session_factory() as db:
        row = build_mqtt_log_row(
            "iot/esp32_01/sensor", '{"device_id":"esp32_01"}',
            datetime(2026, 9, 30, 0, 0, 4, tzinfo=timezone.utc),
        )
        insert_mqtt_log(db, row)
        raw = db.execute(text("""SELECT device_id, error_message
            FROM mqtt_logs""")).mappings().one()
        assert raw["device_id"] == "esp32_01"
        assert "disabled_device_communication" in raw["error_message"]
        assert db.execute(text("SELECT last_seen_at FROM devices")).scalar_one() is None
        db.rollback()
        with db.begin():
            produced = produce_mqtt_features_until(db, producer_cutoff=T1)
        assert produced.created_feature_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar_one() == 0
