from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from db.migration_runner import MIGRATIONS_DIR, apply_migrations
from edge.detection import mqtt_adapters
from edge.detection.detection_event_writer import write_detection_event
from edge.detection.detector_contract import DetectorRunResult
from edge.detection.mqtt_adapters import (
    MqttFeatureRuleStage,
    MqttIsolationForestStage,
    MqttMessageRuleStage,
)
from edge.detection.orchestrator import run_detection_cycle
from edge.detection.runtime_checkpoint_repository import (
    get_detector_checkpoint,
    upsert_detector_checkpoint,
)
from edge.features.collect_feature_logs import produce_mqtt_features_until
from edge.trust.trust_policy import incident_family_for_event


CUTOVER = datetime(2026, 7, 23, 10, 0, 20, tzinfo=timezone.utc)
RANGE_START = datetime(2026, 7, 23, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "phase4-detection-core.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield TestingSessionLocal
    finally:
        engine.dispose()


def test_runtime_checkpoint_adapter_is_transaction_controlled(SessionLocal) -> None:
    with SessionLocal() as db:
        transaction = db.begin()
        upsert_detector_checkpoint(
            db,
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
            last_processed_id=10,
            last_completed_window_end=CUTOVER,
            updated_at=CUTOVER,
        )
        transaction.rollback()

        assert get_detector_checkpoint(
            db,
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
        ) is None
        with pytest.raises(ValueError, match="unknown Phase 4 checkpoint"):
            upsert_detector_checkpoint(
                db,
                detector_name="new_detector",
                source_table="feature_logs",
                last_processed_id=None,
                last_completed_window_end=None,
                updated_at=CUTOVER,
            )
        with pytest.raises(ValueError, match="whole-second"):
            upsert_detector_checkpoint(
                db,
                detector_name="mqtt_feature_rule",
                source_table="feature_logs",
                last_processed_id=None,
                last_completed_window_end=None,
                updated_at=datetime(2026, 7, 23, 10, 0, 20, 1, tzinfo=timezone.utc),
            )
        upsert_detector_checkpoint(
            db,
            detector_name="mqtt_message_rule",
            source_table="mqtt_logs",
            last_processed_id=None,
            last_completed_window_end=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
            updated_at=CUTOVER,
        )
        with pytest.raises(ValueError, match="10 second boundary"):
            upsert_detector_checkpoint(
                db,
                detector_name="mqtt_if",
                source_table="feature_logs",
                last_processed_id=None,
                last_completed_window_end=datetime(2026, 7, 23, 10, 0, 7, tzinfo=timezone.utc),
                updated_at=CUTOVER,
            )
        with pytest.raises(ValueError, match="whole-second"):
            upsert_detector_checkpoint(
                db,
                detector_name="packet_rule",
                source_table="packet_feature_logs",
                last_processed_id=None,
                last_completed_window_end=datetime(2026, 7, 23, 10, 0, 10, 1, tzinfo=timezone.utc),
                updated_at=CUTOVER,
            )


def test_incident_family_mapping_covers_phase4_event_types() -> None:
    expected = {
        "UNKNOWN_DEVICE": "IDENTITY",
        "DEVICE_ID_MISMATCH": "IDENTITY",
        "LARGE_PAYLOAD": "MESSAGE_POLICY",
        "MALFORMED_PAYLOAD": "MESSAGE_POLICY",
        "ABNORMAL_TOPIC": "MESSAGE_POLICY",
        "ABNORMAL_PUBLISH_RATE": "FLOODING",
        "PACKET_RATE_ANOMALY": "FLOODING",
        "BYTE_RATE_ANOMALY": "FLOODING",
        "BROKER_DOS_SUSPECTED": "FLOODING",
        "NON_MQTT_TRAFFIC": "NETWORK_POLICY",
        "PORT_SCAN": "SCAN",
        "AI_ANOMALY": "AI_ONLY",
        "AI_PACKET_ANOMALY": "AI_ONLY",
    }

    for event_type, family in expected.items():
        assert incident_family_for_event(event_type) == family


def test_mqtt_feature_producer_creates_features_and_checkpoint_in_one_transaction(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01")
        _insert_mqtt_log(db, "esp32_01", "2026-07-23T10:00:01Z", payload_size=100)
        _insert_mqtt_log(db, "esp32_01", "2026-07-23T10:00:11Z", payload_size=200)
        db.commit()

    with SessionLocal() as db:
        transaction = db.begin()
        result = produce_mqtt_features_until(db, producer_cutoff=CUTOVER)
        assert result.selected_count == 2
        assert result.created_feature_count == 2
        assert result.completed_window_end_after == CUTOVER
        transaction.rollback()

    with SessionLocal() as db:
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar_one() == 0
        assert db.execute(text("SELECT COUNT(*) FROM detector_checkpoints")).scalar_one() == 0

    with SessionLocal() as db:
        with db.begin():
            produce_mqtt_features_until(db, producer_cutoff=CUTOVER)
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar_one() == 2
        windows = db.execute(
            text(
                """
                SELECT window_start, window_end
                FROM feature_logs
                ORDER BY id
                """
            )
        ).mappings().all()
        assert windows[0]["window_start"] == "2026-07-23T10:00:00Z"
        assert windows[0]["window_end"] == "2026-07-23T10:00:10Z"
        checkpoint = get_detector_checkpoint(
            db,
            detector_name="mqtt_feature_builder",
            source_table="mqtt_logs",
        )
        assert checkpoint["last_processed_id"] == 2
        assert checkpoint["last_completed_window_end"] == "2026-07-23T10:00:20Z"


def test_mqtt_feature_producer_consumes_late_source_without_reopening_window(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01")
        _insert_mqtt_log(db, "esp32_01", "2026-07-23T10:00:01Z", payload_size=100)
        db.commit()
        with db.begin():
            produce_mqtt_features_until(db, producer_cutoff=CUTOVER)
        _insert_mqtt_log(db, "esp32_01", "2026-07-23T10:00:05Z", payload_size=999)
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = produce_mqtt_features_until(
                db,
                producer_cutoff=datetime(2026, 7, 23, 10, 0, 30, tzinfo=timezone.utc),
            )

        assert result.late_source_count == 1
        assert result.created_feature_count == 0
        assert db.execute(text("SELECT COUNT(*) FROM feature_logs")).scalar_one() == 1
        checkpoint = get_detector_checkpoint(
            db,
            detector_name="mqtt_feature_builder",
            source_table="mqtt_logs",
        )
        assert checkpoint["last_processed_id"] == 2
        assert checkpoint["last_completed_window_end"] == "2026-07-23T10:00:30Z"


def test_mqtt_feature_producer_does_not_skip_lower_id_future_source(
    SessionLocal,
) -> None:
    first_cutoff = CUTOVER
    second_cutoff = datetime(2026, 7, 23, 10, 0, 30, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01")
        _insert_mqtt_log(
            db,
            "esp32_01",
            "2026-07-23T10:00:21Z",
            payload_size=300,
            mqtt_id=10,
        )
        _insert_mqtt_log(
            db,
            "esp32_01",
            "2026-07-23T10:00:01Z",
            payload_size=100,
            mqtt_id=11,
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            first = produce_mqtt_features_until(db, producer_cutoff=first_cutoff)

        assert first.created_feature_count == 1
        assert db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM feature_logs
                WHERE window_start = '2026-07-23T10:00:00Z'
                  AND window_end = '2026-07-23T10:00:10Z'
                """
            )
        ).scalar_one() == 1
        db.rollback()

        with db.begin():
            second = produce_mqtt_features_until(db, producer_cutoff=second_cutoff)

        assert second.created_feature_count == 1
        assert db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM feature_logs
                WHERE window_start = '2026-07-23T10:00:20Z'
                  AND window_end = '2026-07-23T10:00:30Z'
                """
            )
        ).scalar_one() == 1


def test_phase4_detection_writer_dedupes_and_validates_source_fk(SessionLocal) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01")
        feature_id = _insert_feature(
            db,
            "esp32_01",
            "2026-07-23T10:00:00Z",
            "2026-07-23T10:00:10Z",
            publish_count=20,
        )
        first = write_detection_event(
            db,
            device_id="esp32_01",
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
            source_id=feature_id,
            detector_type="RULE",
            event_type="ABNORMAL_PUBLISH_RATE",
            severity="high",
            description="test",
            policy_version="mqtt-feature-rule-v1",
            detected_at=CUTOVER,
            analysis_window_start=RANGE_START,
            analysis_window_end=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
            feature_log_id=feature_id,
            evidence={"b": 2, "a": 1},
        )
        second = write_detection_event(
            db,
            device_id="esp32_01",
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
            source_id=feature_id,
            detector_type="RULE",
            event_type="ABNORMAL_PUBLISH_RATE",
            severity="high",
            description="test",
            policy_version="mqtt-feature-rule-v1",
            detected_at=CUTOVER,
            analysis_window_start=RANGE_START,
            analysis_window_end=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
            feature_log_id=feature_id,
        )

        assert first.inserted is True
        assert second.duplicate is True
        assert second.event_id == first.event_id
        assert db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar_one() == 1
        event_row = db.execute(
            text("SELECT incident_family, evidence_json FROM detection_events")
        ).mappings().one()
        assert event_row["incident_family"] == "FLOODING"
        evidence_json = event_row["evidence_json"]
        assert evidence_json == '{"a":1,"b":2}'
        with pytest.raises(ValueError, match="incident_family must match"):
            write_detection_event(
                db,
                device_id="esp32_01",
                detector_name="mqtt_feature_rule",
                source_table="feature_logs",
                source_id=feature_id,
                detector_type="RULE",
                event_type="ABNORMAL_PUBLISH_RATE",
                severity="high",
                description="bad family",
                policy_version="mqtt-feature-rule-v1",
                detected_at=CUTOVER,
                analysis_window_start=RANGE_START,
                analysis_window_end=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
                incident_family="IDENTITY",
                feature_log_id=feature_id,
            )
        with pytest.raises(ValueError, match="unknown incident family policy"):
            write_detection_event(
                db,
                device_id="esp32_01",
                detector_name="mqtt_feature_rule",
                source_table="feature_logs",
                source_id=feature_id,
                detector_type="RULE",
                event_type="UNREGISTERED_EVENT",
                severity="high",
                description="unknown event",
                policy_version="mqtt-feature-rule-v1",
                detected_at=CUTOVER,
                analysis_window_start=RANGE_START,
                analysis_window_end=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
                feature_log_id=feature_id,
            )
        with pytest.raises(ValueError, match="exactly one source FK"):
            write_detection_event(
                db,
                device_id="esp32_01",
                detector_name="mqtt_feature_rule",
                source_table="feature_logs",
                source_id=feature_id,
                detector_type="RULE",
                event_type="ABNORMAL_PUBLISH_RATE",
                severity="high",
                description="bad",
                policy_version="mqtt-feature-rule-v1",
                detected_at=CUTOVER,
                analysis_window_start=RANGE_START,
                analysis_window_end=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
            )


def test_mqtt_adapters_create_events_and_advance_checkpoints(SessionLocal, monkeypatch) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", ip_address="192.168.0.10")
        _insert_device(db, "esp32_02", ip_address="192.168.0.11")
        feature_id = _insert_feature(
            db,
            "esp32_01",
            "2026-07-23T10:00:00Z",
            "2026-07-23T10:00:10Z",
            publish_count=20,
        )
        mqtt_id = _insert_mqtt_log(
            db,
            "esp32_01",
            "2026-07-23T10:00:01Z",
            topic="iot/esp32_01/sensor",
            payload='{"device_id":"esp32_02"}',
        )
        db.commit()

    def fake_predict(feature_row, model_path):
        return {
            "is_anomaly": True,
            "prediction": -1,
            "anomaly_score": -0.12,
            "event_type": "AI_ANOMALY",
        }

    monkeypatch.setattr(mqtt_adapters, "predict_feature_window", fake_predict)

    with SessionLocal() as db:
        with db.begin():
            feature_result = MqttFeatureRuleStage().run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOVER,
            )
            message_result = MqttMessageRuleStage().run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOVER,
            )
            ai_result = MqttIsolationForestStage().run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOVER,
            )

        assert feature_result.created_event_count == 1
        assert message_result.created_event_count == 1
        assert ai_result.created_event_count == 1
        rows = db.execute(
            text(
                """
                SELECT detector_type, event_type, feature_log_id, mqtt_log_id,
                       incident_family, subject_ip, processed_at, dedupe_key
                FROM detection_events
                ORDER BY id ASC
                """
            )
        ).mappings().all()
        assert len(rows) == 3
        assert rows[0]["feature_log_id"] == feature_id
        assert rows[1]["mqtt_log_id"] == mqtt_id
        assert rows[2]["event_type"] == "AI_ANOMALY"
        assert rows[0]["incident_family"] == "FLOODING"
        assert rows[1]["incident_family"] == "IDENTITY"
        assert rows[2]["incident_family"] == "AI_ONLY"
        assert rows[0]["subject_ip"] == "192.168.0.10"
        assert rows[1]["subject_ip"] == "192.168.0.10"
        assert rows[2]["subject_ip"] == "192.168.0.10"
        assert all(row["processed_at"] is None for row in rows)
        assert all(row["dedupe_key"] for row in rows)


def test_mqtt_adapters_do_not_move_checkpoints_backwards(SessionLocal) -> None:
    stages = (
        MqttFeatureRuleStage(),
        MqttMessageRuleStage(),
        MqttIsolationForestStage(),
    )
    for stage in stages:
        with SessionLocal() as db:
            with db.begin():
                upsert_detector_checkpoint(
                    db,
                    detector_name=stage.detector_name,
                    source_table=stage.source_table,
                    last_processed_id=10,
                    last_completed_window_end=CUTOVER,
                    updated_at=CUTOVER,
                )

        with SessionLocal() as db:
            with pytest.raises(ValueError, match="cannot move backwards"):
                with db.begin():
                    stage.run_until(
                        db,
                        cycle_range_start=RANGE_START,
                        cycle_cutoff=datetime(2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc),
                    )

            checkpoint = get_detector_checkpoint(
                db,
                detector_name=stage.detector_name,
                source_table=stage.source_table,
            )
            assert checkpoint["last_processed_id"] == 10
            assert checkpoint["last_completed_window_end"] == "2026-07-23T10:00:20Z"


def test_mqtt_feature_rule_adapter_does_not_skip_lower_id_future_window(
    SessionLocal,
) -> None:
    next_cutoff = datetime(2026, 7, 23, 10, 0, 30, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_device(db, "esp32_01")
        future_feature_id = _insert_feature(
            db,
            "esp32_01",
            "2026-07-23T10:00:20Z",
            "2026-07-23T10:00:30Z",
            publish_count=20,
            feature_id=10,
        )
        current_feature_id = _insert_feature(
            db,
            "esp32_01",
            "2026-07-23T10:00:00Z",
            "2026-07-23T10:00:10Z",
            publish_count=20,
            feature_id=11,
        )
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            first = MqttFeatureRuleStage().run_until(
                db,
                cycle_range_start=RANGE_START,
                cycle_cutoff=CUTOVER,
            )

        assert first.created_event_count == 1
        assert db.execute(
            text(
                """
                SELECT feature_log_id
                FROM detection_events
                WHERE feature_log_id = :feature_log_id
                """
            ),
            {"feature_log_id": current_feature_id},
        ).scalar_one() == current_feature_id
        db.rollback()

        with db.begin():
            second = MqttFeatureRuleStage().run_until(
                db,
                cycle_range_start=CUTOVER,
                cycle_cutoff=next_cutoff,
            )

        assert second.created_event_count == 1
        assert db.execute(
            text(
                """
                SELECT feature_log_id
                FROM detection_events
                WHERE feature_log_id = :feature_log_id
                """
            ),
            {"feature_log_id": future_feature_id},
        ).scalar_one() == future_feature_id


def test_orchestrator_commits_successful_stage_before_later_failure(SessionLocal) -> None:
    class SuccessStage:
        detector_name = "mqtt_feature_rule"
        source_table = "feature_logs"

        def run_until(self, db, *, cycle_range_start, cycle_cutoff):
            upsert_detector_checkpoint(
                db,
                detector_name=self.detector_name,
                source_table=self.source_table,
                last_processed_id=1,
                last_completed_window_end=cycle_cutoff,
                updated_at=cycle_cutoff,
            )
            return DetectorRunResult(
                detector_name=self.detector_name,
                source_table=self.source_table,
                range_start=cycle_range_start,
                cutoff=cycle_cutoff,
                selected_count=0,
                created_event_count=0,
                last_processed_id_before=None,
                last_processed_id_after=1,
                completed_window_end_before=None,
                completed_window_end_after=cycle_cutoff,
            )

    class FailingStage:
        detector_name = "mqtt_message_rule"
        source_table = "mqtt_logs"

        def run_until(self, db, *, cycle_range_start, cycle_cutoff):
            upsert_detector_checkpoint(
                db,
                detector_name=self.detector_name,
                source_table=self.source_table,
                last_processed_id=2,
                last_completed_window_end=cycle_cutoff,
                updated_at=cycle_cutoff,
            )
            raise RuntimeError("stage failed")

    with pytest.raises(RuntimeError, match="stage failed"):
        run_detection_cycle(
            session_factory=SessionLocal,
            stages=[SuccessStage(), FailingStage()],
            cycle_range_start=RANGE_START,
            cycle_cutoff=CUTOVER,
        )

    with SessionLocal() as db:
        assert get_detector_checkpoint(
            db,
            detector_name="mqtt_feature_rule",
            source_table="feature_logs",
        )["last_processed_id"] == 1
        assert get_detector_checkpoint(
            db,
            detector_name="mqtt_message_rule",
            source_table="mqtt_logs",
        ) is None


def _insert_device(db, device_id: str, ip_address: str = "192.168.0.10") -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, :ip_address, 'normal', 100)
            """
        ),
        {"device_id": device_id, "ip_address": ip_address},
    )


def _insert_mqtt_log(
    db,
    device_id: str,
    received_at: str,
    *,
    mqtt_id: int | None = None,
    topic: str = "iot/esp32_01/sensor",
    payload: str = '{"device_id":"esp32_01"}',
    payload_size: int = 100,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                id,
                device_id, topic, payload, payload_size,
                received_at, is_json_valid, is_topic_valid
            )
            VALUES (
                :id, :device_id, :topic, :payload, :payload_size,
                :received_at, 1, 1
            )
            """
        ),
        {
            "id": mqtt_id,
            "device_id": device_id,
            "topic": topic,
            "payload": payload,
            "payload_size": payload_size,
            "received_at": received_at,
        },
    )
    return int(result.lastrowid)


def _insert_feature(
    db,
    device_id: str,
    window_start: str,
    window_end: str,
    *,
    publish_count: int,
    feature_id: int | None = None,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO feature_logs (
                id,
                device_id,
                window_start,
                window_end,
                publish_count,
                avg_payload_size,
                max_payload_size,
                avg_message_interval,
                min_message_interval,
                topic_count,
                abnormal_topic_count,
                malformed_payload_count
            )
            VALUES (
                :id,
                :device_id,
                :window_start,
                :window_end,
                :publish_count,
                100.0,
                100,
                0.5,
                0.5,
                1,
                0,
                0
            )
            """
        ),
        {
            "id": feature_id,
            "device_id": device_id,
            "window_start": window_start,
            "window_end": window_end,
            "publish_count": publish_count,
        },
    )
    return int(result.lastrowid)
