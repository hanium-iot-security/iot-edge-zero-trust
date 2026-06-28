"""run_rule_detector 통합 테스트. 실제 SQLite DB를 사용합니다."""

from unittest.mock import patch

import pytest
from sqlalchemy import text

from edge.detection.run_rule_detector import run_rule_detector
from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    ABNORMAL_TOPIC,
    DETECTOR_RULE,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    UNKNOWN_DEVICE,
)


# ── 픽스처 ────────────────────────────────────────────────────────────────────

def _cleanup(db) -> None:
    for table in ("detection_events", "feature_logs", "mqtt_logs", "isolation_history", "devices"):
        db.execute(text(f"DELETE FROM {table}"))
    db.commit()


@pytest.fixture()
def fresh_db(db_session):
    """각 테스트 전후 모든 테이블을 비워 테스트 간 DB 오염을 방지합니다."""
    _cleanup(db_session)
    try:
        yield db_session
    finally:
        db_session.rollback()
        _cleanup(db_session)


# ── DB 삽입 헬퍼 ──────────────────────────────────────────────────────────────

def _device(db, device_id="esp32_01"):
    db.execute(
        text(
            "INSERT INTO devices (device_id, trust_score, status) "
            "VALUES (:device_id, 100, 'normal')"
        ),
        {"device_id": device_id},
    )


def _feature_log(db, device_id="esp32_01", **overrides):
    defaults = {
        "publish_count": 2,
        "min_message_interval": 5.0,
        "max_payload_size": 100,
        "malformed_payload_count": 0,
        "abnormal_topic_count": 0,
        "avg_payload_size": 100.0,
        "avg_message_interval": 5.0,
    }
    defaults.update(overrides)
    db.execute(
        text(
            """
            INSERT INTO feature_logs (
                device_id, window_start, window_end,
                publish_count, avg_payload_size, max_payload_size,
                avg_message_interval, min_message_interval,
                malformed_payload_count, abnormal_topic_count
            )
            VALUES (
                :device_id,
                datetime('now', '-20 seconds'),
                datetime('now', '-10 seconds'),
                :publish_count, :avg_payload_size, :max_payload_size,
                :avg_message_interval, :min_message_interval,
                :malformed_payload_count, :abnormal_topic_count
            )
            """
        ),
        {"device_id": device_id, **defaults},
    )
    return db.execute(text("SELECT last_insert_rowid()")).scalar()


def _mqtt_log(db, topic, payload, device_id=None):
    db.execute(
        text(
            """
            INSERT INTO mqtt_logs (device_id, topic, payload, payload_size, is_json_valid, is_topic_valid)
            VALUES (:device_id, :topic, :payload, :size, 1, 1)
            """
        ),
        {"device_id": device_id, "topic": topic, "payload": payload, "size": len(payload)},
    )
    return db.execute(text("SELECT last_insert_rowid()")).scalar()


def _event_count(db):
    return db.execute(text("SELECT COUNT(*) FROM detection_events")).scalar()


def _event_types(db):
    return [r[0] for r in db.execute(text("SELECT event_type FROM detection_events")).fetchall()]


# ── 빈 테이블 ────────────────────────────────────────────────────────────────

class TestEmptyTables:
    def test_no_rows_returns_zero_counts(self, fresh_db):
        result = run_rule_detector(fresh_db)
        assert result == {"feature_events": 0, "mqtt_events": 0}

    def test_no_rows_no_events_inserted(self, fresh_db):
        run_rule_detector(fresh_db)
        assert _event_count(fresh_db) == 0


# ── feature_logs 처리 ────────────────────────────────────────────────────────

class TestFeatureLogs:
    def test_normal_feature_log_creates_no_event(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db)
        result = run_rule_detector(fresh_db)
        assert result["feature_events"] == 0
        assert _event_count(fresh_db) == 0

    def test_high_publish_count_creates_event(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=16)
        result = run_rule_detector(fresh_db)
        assert result["feature_events"] == 1
        assert ABNORMAL_PUBLISH_RATE in _event_types(fresh_db)

    def test_large_payload_creates_event(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, max_payload_size=5121)
        result = run_rule_detector(fresh_db)
        assert LARGE_PAYLOAD in _event_types(fresh_db)

    def test_malformed_payload_creates_event(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, malformed_payload_count=3)
        result = run_rule_detector(fresh_db)
        assert MALFORMED_PAYLOAD in _event_types(fresh_db)

    def test_abnormal_topic_creates_event(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, abnormal_topic_count=3)
        result = run_rule_detector(fresh_db)
        assert ABNORMAL_TOPIC in _event_types(fresh_db)

    def test_multiple_conditions_creates_multiple_events(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=20, max_payload_size=6000, malformed_payload_count=4)
        result = run_rule_detector(fresh_db)
        assert result["feature_events"] == 3
        types = _event_types(fresh_db)
        assert ABNORMAL_PUBLISH_RATE in types
        assert LARGE_PAYLOAD in types
        assert MALFORMED_PAYLOAD in types

    def test_device_id_stored_in_event(self, fresh_db):
        _device(fresh_db, device_id="esp32_77")
        _feature_log(fresh_db, device_id="esp32_77", publish_count=20)
        run_rule_detector(fresh_db)
        row = fresh_db.execute(text("SELECT device_id FROM detection_events")).fetchone()
        assert row[0] == "esp32_77"

    def test_feature_log_id_stored_in_event(self, fresh_db):
        _device(fresh_db)
        fid = _feature_log(fresh_db, publish_count=20)
        run_rule_detector(fresh_db)
        row = fresh_db.execute(text("SELECT feature_log_id FROM detection_events")).fetchone()
        assert row[0] == fid

    def test_detector_type_is_rule(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=20)
        run_rule_detector(fresh_db)
        row = fresh_db.execute(text("SELECT detector_type FROM detection_events")).fetchone()
        assert row[0] == DETECTOR_RULE

    def test_events_committed_to_db(self, fresh_db):
        """runner가 commit을 수행했는지 검증: rollback 후에도 데이터가 남아있어야 함."""
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=20)
        run_rule_detector(fresh_db)
        fresh_db.rollback()
        assert _event_count(fresh_db) == 1

    def test_partial_failure_rolls_back_all(self, fresh_db):
        """중간 저장 실패 시 이미 저장된 이벤트도 함께 롤백되어야 합니다."""
        _device(fresh_db)
        # publish rate + large payload 두 이벤트가 발생하도록 설정
        _feature_log(fresh_db, publish_count=20, max_payload_size=6000)

        import edge.detection.run_rule_detector as module
        original = module.insert_detection_event
        call_count = [0]

        def fail_on_second(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                raise RuntimeError("simulated DB error")
            return original(*args, **kwargs)

        with patch.object(module, "insert_detection_event", fail_on_second):
            with pytest.raises(RuntimeError):
                run_rule_detector(fresh_db)

        assert _event_count(fresh_db) == 0


# ── mqtt_logs 처리 ────────────────────────────────────────────────────────────

class TestMqttLogs:
    def test_registered_matching_ids_creates_no_event(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        _mqtt_log(fresh_db, "iot/esp32_01/sensor", '{"device_id":"esp32_01"}')
        result = run_rule_detector(fresh_db)
        assert result["mqtt_events"] == 0
        assert _event_count(fresh_db) == 0

    def test_unknown_device_creates_event(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        _mqtt_log(fresh_db, "iot/rogue_device/sensor", '{"device_id":"rogue_device"}')
        result = run_rule_detector(fresh_db)
        assert result["mqtt_events"] == 1
        assert UNKNOWN_DEVICE in _event_types(fresh_db)

    def test_unknown_device_id_stored(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        _mqtt_log(fresh_db, "iot/rogue_device/sensor", '{"device_id":"rogue_device"}')
        run_rule_detector(fresh_db)
        row = fresh_db.execute(text("SELECT device_id FROM detection_events")).fetchone()
        assert row[0] == "rogue_device"

    def test_device_id_mismatch_creates_event(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        _device(fresh_db, device_id="esp32_02")
        _mqtt_log(fresh_db, "iot/esp32_01/sensor", '{"device_id":"esp32_02"}')
        result = run_rule_detector(fresh_db)
        assert result["mqtt_events"] == 1
        assert DEVICE_ID_MISMATCH in _event_types(fresh_db)

    def test_mqtt_log_id_stored_in_event(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        mid = _mqtt_log(fresh_db, "iot/rogue/sensor", '{"device_id":"rogue"}')
        run_rule_detector(fresh_db)
        row = fresh_db.execute(text("SELECT mqtt_log_id FROM detection_events")).fetchone()
        assert row[0] == mid


# ── 중복 재실행 방지 ──────────────────────────────────────────────────────────

class TestIdempotency:
    def test_rerun_does_not_duplicate_feature_events(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=20)
        run_rule_detector(fresh_db)
        run_rule_detector(fresh_db)
        assert _event_count(fresh_db) == 1

    def test_rerun_does_not_duplicate_mqtt_events(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        _mqtt_log(fresh_db, "iot/rogue/sensor", '{"device_id":"rogue"}')
        run_rule_detector(fresh_db)
        run_rule_detector(fresh_db)
        assert _event_count(fresh_db) == 1

    def test_second_run_returns_zero_counts(self, fresh_db):
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=20)
        run_rule_detector(fresh_db)
        result = run_rule_detector(fresh_db)
        assert result == {"feature_events": 0, "mqtt_events": 0}

    def test_partial_event_in_window_is_not_skipped_on_rerun(self, fresh_db):
        """첫 실행에서 일부 이벤트(publish rate)만 저장된 상태에서 재실행 시
        나머지 이벤트(large payload)도 저장되어야 합니다."""
        _device(fresh_db)
        _feature_log(fresh_db, publish_count=20, max_payload_size=6000)

        import edge.detection.run_rule_detector as module
        original = module.insert_detection_event
        call_count = [0]

        def only_first(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                return None  # writer 중복처럼 None 반환 (저장 안 함)
            return original(*args, **kwargs)

        with patch.object(module, "insert_detection_event", only_first):
            run_rule_detector(fresh_db)

        assert _event_count(fresh_db) == 1

        # 재실행 — writer가 실제 중복만 걸러야 하므로 누락된 이벤트가 저장되어야 함
        result = run_rule_detector(fresh_db)
        assert result["feature_events"] == 1
        assert _event_count(fresh_db) == 2


# ── feature + mqtt 동시 처리 ──────────────────────────────────────────────────

class TestMixedLogs:
    def test_feature_and_mqtt_both_processed(self, fresh_db):
        _device(fresh_db, device_id="esp32_01")
        _feature_log(fresh_db, device_id="esp32_01", publish_count=20)
        _mqtt_log(fresh_db, "iot/rogue/sensor", '{"device_id":"rogue"}')
        result = run_rule_detector(fresh_db)
        assert result["feature_events"] == 1
        assert result["mqtt_events"] == 1
        assert _event_count(fresh_db) == 2
