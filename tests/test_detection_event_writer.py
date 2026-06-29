"""detection_event_writer 단위 테스트."""

import pytest
from sqlalchemy import text

from edge.detection.detection_event_writer import insert_detection_event
from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    ABNORMAL_TOPIC,
    AI_ANOMALY,
    DETECTOR_AI,
    DETECTOR_RULE,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    UNKNOWN_DEVICE,
)


# ── 헬퍼 ─────────────────────────────────────────────────────────────────────

def _insert_feature(db, event_type=ABNORMAL_PUBLISH_RATE, feature_log_id=1, device_id="esp32_01"):
    return insert_detection_event(
        db,
        device_id=device_id,
        detector_type=DETECTOR_RULE,
        event_type=event_type,
        severity="high",
        description="test",
        feature_log_id=feature_log_id,
    )


def _insert_mqtt(db, event_type=UNKNOWN_DEVICE, mqtt_log_id=1, device_id="rogue_01"):
    return insert_detection_event(
        db,
        device_id=device_id,
        detector_type=DETECTOR_RULE,
        event_type=event_type,
        severity="high",
        description="test",
        mqtt_log_id=mqtt_log_id,
    )


def _row_count(db) -> int:
    return db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar()


# ── 입력 검증 ─────────────────────────────────────────────────────────────────

class TestValidation:
    def test_both_ids_none_raises(self, db_session):
        with pytest.raises(ValueError, match="정확히 하나"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type=DETECTOR_RULE,
                event_type=ABNORMAL_PUBLISH_RATE,
                severity="high",
                description="test",
            )

    def test_both_ids_provided_raises(self, db_session):
        with pytest.raises(ValueError, match="정확히 하나"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type=DETECTOR_RULE,
                event_type=ABNORMAL_PUBLISH_RATE,
                severity="high",
                description="test",
                feature_log_id=1,
                mqtt_log_id=1,
            )

    def test_unknown_detector_type_raises(self, db_session):
        with pytest.raises(ValueError, match="detector_type"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type="UNKNOWN",
                event_type=ABNORMAL_PUBLISH_RATE,
                severity="high",
                description="test",
                feature_log_id=1,
            )

    def test_rule_detector_with_ai_event_raises(self, db_session):
        with pytest.raises(ValueError, match="event_type"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type=DETECTOR_RULE,
                event_type=AI_ANOMALY,
                severity="medium",
                description="test",
                feature_log_id=1,
            )

    def test_ai_detector_with_rule_event_raises(self, db_session):
        with pytest.raises(ValueError, match="event_type"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type=DETECTOR_AI,
                event_type=ABNORMAL_PUBLISH_RATE,
                severity="high",
                description="test",
                feature_log_id=1,
            )

    def test_mqtt_based_event_with_feature_log_id_raises(self, db_session):
        with pytest.raises(ValueError, match="mqtt_log_id"):
            insert_detection_event(
                db_session,
                device_id="rogue",
                detector_type=DETECTOR_RULE,
                event_type=UNKNOWN_DEVICE,
                severity="high",
                description="test",
                feature_log_id=1,
            )

    def test_feature_based_event_with_mqtt_log_id_raises(self, db_session):
        with pytest.raises(ValueError, match="feature_log_id"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type=DETECTOR_RULE,
                event_type=ABNORMAL_PUBLISH_RATE,
                severity="high",
                description="test",
                mqtt_log_id=1,
            )

    def test_invalid_severity_raises(self, db_session):
        with pytest.raises(ValueError, match="severity"):
            insert_detection_event(
                db_session,
                device_id="esp32_01",
                detector_type=DETECTOR_RULE,
                event_type=ABNORMAL_PUBLISH_RATE,
                severity="critical",
                description="test",
                feature_log_id=1,
            )


# ── 정상 저장 ─────────────────────────────────────────────────────────────────

class TestInsert:
    def test_returns_integer_id(self, db_session):
        event_id = _insert_feature(db_session)
        assert isinstance(event_id, int)
        assert event_id > 0

    def test_row_is_persisted(self, db_session):
        _insert_feature(db_session)
        assert _row_count(db_session) == 1

    def test_applied_to_score_is_zero(self, db_session):
        _insert_feature(db_session)
        row = db_session.execute(text("SELECT applied_to_score FROM detection_events")).fetchone()
        assert row[0] == 0

    def test_feature_log_id_stored(self, db_session):
        _insert_feature(db_session, feature_log_id=42)
        row = db_session.execute(text("SELECT feature_log_id FROM detection_events")).fetchone()
        assert row[0] == 42

    def test_mqtt_log_id_stored(self, db_session):
        _insert_mqtt(db_session, mqtt_log_id=99)
        row = db_session.execute(text("SELECT mqtt_log_id FROM detection_events")).fetchone()
        assert row[0] == 99

    def test_does_not_commit(self, db_session):
        _insert_feature(db_session)
        db_session.rollback()
        assert _row_count(db_session) == 0

    def test_all_fields_stored_correctly(self, db_session):
        insert_detection_event(
            db_session,
            device_id="esp32_01",
            detector_type=DETECTOR_RULE,
            event_type=ABNORMAL_PUBLISH_RATE,
            severity="high",
            description="publish rate exceeded",
            feature_log_id=7,
        )
        row = db_session.execute(
            text(
                "SELECT device_id, detector_type, event_type, severity, "
                "score_delta, applied_to_score, description, feature_log_id, mqtt_log_id "
                "FROM detection_events"
            )
        ).fetchone()
        assert row[0] == "esp32_01"
        assert row[1] == DETECTOR_RULE
        assert row[2] == ABNORMAL_PUBLISH_RATE
        assert row[3] == "high"
        assert row[4] == -20
        assert row[5] == 0
        assert row[6] == "publish rate exceeded"
        assert row[7] == 7
        assert row[8] is None


# ── score_delta 정책 ──────────────────────────────────────────────────────────

class TestScoreDelta:
    @pytest.mark.parametrize("event_type,expected_delta", [
        (ABNORMAL_PUBLISH_RATE, -20),
        (LARGE_PAYLOAD,         -15),
        (MALFORMED_PAYLOAD,     -10),
        (ABNORMAL_TOPIC,        -20),
        (AI_ANOMALY,            -15),
    ])
    def test_feature_event_score_delta(self, db_session, event_type, expected_delta):
        detector = DETECTOR_AI if event_type == AI_ANOMALY else DETECTOR_RULE
        insert_detection_event(
            db_session,
            device_id="esp32_01",
            detector_type=detector,
            event_type=event_type,
            severity="medium",
            description="test",
            feature_log_id=1,
        )
        row = db_session.execute(text("SELECT score_delta FROM detection_events")).fetchone()
        assert row[0] == expected_delta

    def test_unknown_device_score_delta_is_zero(self, db_session):
        _insert_mqtt(db_session, event_type=UNKNOWN_DEVICE)
        row = db_session.execute(text("SELECT score_delta FROM detection_events")).fetchone()
        assert row[0] == 0

    def test_device_id_mismatch_score_delta(self, db_session):
        _insert_mqtt(db_session, event_type=DEVICE_ID_MISMATCH, device_id="esp32_01")
        row = db_session.execute(text("SELECT score_delta FROM detection_events")).fetchone()
        assert row[0] == -25


# ── 중복 방지 ─────────────────────────────────────────────────────────────────

class TestDuplicatePrevention:
    def test_duplicate_feature_event_returns_none(self, db_session):
        _insert_feature(db_session, feature_log_id=1)
        result = _insert_feature(db_session, feature_log_id=1)
        assert result is None

    def test_duplicate_feature_event_does_not_insert(self, db_session):
        _insert_feature(db_session, feature_log_id=1)
        _insert_feature(db_session, feature_log_id=1)
        assert _row_count(db_session) == 1

    def test_duplicate_mqtt_event_returns_none(self, db_session):
        _insert_mqtt(db_session, mqtt_log_id=1)
        result = _insert_mqtt(db_session, mqtt_log_id=1)
        assert result is None

    def test_different_feature_log_id_is_not_duplicate(self, db_session):
        _insert_feature(db_session, feature_log_id=1)
        result = _insert_feature(db_session, feature_log_id=2)
        assert result is not None
        assert _row_count(db_session) == 2

    def test_different_event_type_same_feature_log_id_is_not_duplicate(self, db_session):
        _insert_feature(db_session, event_type=ABNORMAL_PUBLISH_RATE, feature_log_id=1)
        result = _insert_feature(db_session, event_type=LARGE_PAYLOAD, feature_log_id=1)
        assert result is not None
        assert _row_count(db_session) == 2

    def test_different_mqtt_log_id_is_not_duplicate(self, db_session):
        _insert_mqtt(db_session, mqtt_log_id=1)
        result = _insert_mqtt(db_session, mqtt_log_id=2)
        assert result is not None
        assert _row_count(db_session) == 2
