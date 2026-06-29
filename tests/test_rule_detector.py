"""rule_detector 순수 판정 함수 단위 테스트. DB 접근 없음."""

from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    ABNORMAL_TOPIC,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    UNKNOWN_DEVICE,
    detect_feature_rules,
    detect_mqtt_rules,
)

REGISTERED = {"esp32_01", "esp32_02"}


# ── feature_row 헬퍼 ──────────────────────────────────────────────────────────

def _feature(
    publish_count: int = 2,
    min_message_interval: float = 5.0,
    max_payload_size: int = 100,
    malformed_payload_count: int = 0,
    abnormal_topic_count: int = 0,
) -> dict:
    return {
        "publish_count": publish_count,
        "min_message_interval": min_message_interval,
        "max_payload_size": max_payload_size,
        "malformed_payload_count": malformed_payload_count,
        "abnormal_topic_count": abnormal_topic_count,
    }


def _mqtt(topic: str, payload: str) -> dict:
    return {"topic": topic, "payload": payload}


def _event_types(events: list[dict]) -> list[str]:
    return [e["event_type"] for e in events]


# ── detect_feature_rules ──────────────────────────────────────────────────────

class TestDetectFeatureRules:

    # ABNORMAL_PUBLISH_RATE — publish_count
    def test_publish_count_15_is_normal(self):
        assert detect_feature_rules(_feature(publish_count=15)) == []

    def test_publish_count_16_triggers(self):
        assert ABNORMAL_PUBLISH_RATE in _event_types(detect_feature_rules(_feature(publish_count=16)))

    # ABNORMAL_PUBLISH_RATE — min_message_interval
    def test_interval_1_0_is_normal(self):
        assert detect_feature_rules(_feature(min_message_interval=1.0)) == []

    def test_interval_below_1_0_triggers(self):
        assert ABNORMAL_PUBLISH_RATE in _event_types(detect_feature_rules(_feature(min_message_interval=0.9)))

    def test_interval_0_0_triggers(self):
        assert ABNORMAL_PUBLISH_RATE in _event_types(detect_feature_rules(_feature(min_message_interval=0.0)))

    # LARGE_PAYLOAD
    def test_payload_5120_is_normal(self):
        assert detect_feature_rules(_feature(max_payload_size=5120)) == []

    def test_payload_5121_triggers(self):
        assert LARGE_PAYLOAD in _event_types(detect_feature_rules(_feature(max_payload_size=5121)))

    # MALFORMED_PAYLOAD
    def test_malformed_count_2_is_normal(self):
        assert detect_feature_rules(_feature(malformed_payload_count=2)) == []

    def test_malformed_count_3_triggers(self):
        assert MALFORMED_PAYLOAD in _event_types(detect_feature_rules(_feature(malformed_payload_count=3)))

    # ABNORMAL_TOPIC
    def test_abnormal_topic_count_2_is_normal(self):
        assert detect_feature_rules(_feature(abnormal_topic_count=2)) == []

    def test_abnormal_topic_count_3_triggers(self):
        assert ABNORMAL_TOPIC in _event_types(detect_feature_rules(_feature(abnormal_topic_count=3)))

    # 정상 row — 이벤트 없음
    def test_normal_row_returns_empty(self):
        assert detect_feature_rules(_feature()) == []

    # 여러 조건 동시 트리거
    def test_multiple_conditions_returns_multiple_events(self):
        row = _feature(publish_count=30, max_payload_size=10000, malformed_payload_count=5)
        types = _event_types(detect_feature_rules(row))
        assert ABNORMAL_PUBLISH_RATE in types
        assert LARGE_PAYLOAD in types
        assert MALFORMED_PAYLOAD in types

    # severity 값 확인
    def test_severity_values(self):
        events = detect_feature_rules(_feature(
            publish_count=30,
            max_payload_size=6000,
            malformed_payload_count=3,
            abnormal_topic_count=3,
        ))
        severity_map = {e["event_type"]: e["severity"] for e in events}
        assert severity_map[ABNORMAL_PUBLISH_RATE] == "high"
        assert severity_map[LARGE_PAYLOAD] == "medium"
        assert severity_map[MALFORMED_PAYLOAD] == "medium"
        assert severity_map[ABNORMAL_TOPIC] == "high"


# ── detect_mqtt_rules ─────────────────────────────────────────────────────────

class TestDetectMqttRules:

    # 정상 — 등록 기기, topic/payload 일치
    def test_registered_matching_ids_returns_empty(self):
        row = _mqtt("iot/esp32_01/sensor", '{"device_id":"esp32_01"}')
        assert detect_mqtt_rules(row, REGISTERED) == []

    # UNKNOWN_DEVICE — topic_id 미등록
    def test_unknown_topic_id_triggers_unknown_device(self):
        row = _mqtt("iot/rogue_device/sensor", '{"device_id":"rogue_device"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert len(events) == 1
        assert events[0]["event_type"] == UNKNOWN_DEVICE

    # UNKNOWN_DEVICE — payload_id 미등록, topic_id 없음
    def test_unknown_payload_id_only_triggers_unknown_device(self):
        row = _mqtt("admin/system/control", '{"device_id":"rogue_device"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert len(events) == 1
        assert events[0]["event_type"] == UNKNOWN_DEVICE

    # UNKNOWN_DEVICE — topic_id 미등록, payload_id 등록 (topic 우선)
    def test_topic_unregistered_payload_registered_triggers_unknown(self):
        row = _mqtt("iot/rogue_device/sensor", '{"device_id":"esp32_01"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert events[0]["event_type"] == UNKNOWN_DEVICE
        assert events[0]["device_id"] == "rogue_device"

    # UNKNOWN_DEVICE — topic_id 등록, payload_id 미등록
    def test_topic_registered_payload_unregistered_triggers_unknown(self):
        row = _mqtt("iot/esp32_01/sensor", '{"device_id":"rogue_device"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert events[0]["event_type"] == UNKNOWN_DEVICE
        assert events[0]["device_id"] == "rogue_device"

    # DEVICE_ID_MISMATCH — 둘 다 등록 기기이지만 서로 다름
    def test_both_registered_but_different_triggers_mismatch(self):
        row = _mqtt("iot/esp32_01/sensor", '{"device_id":"esp32_02"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert len(events) == 1
        assert events[0]["event_type"] == DEVICE_ID_MISMATCH
        assert events[0]["device_id"] == "esp32_01"

    # DEVICE_ID_MISMATCH device_id는 topic_id
    def test_mismatch_device_id_is_topic_id(self):
        row = _mqtt("iot/esp32_02/sensor", '{"device_id":"esp32_01"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert events[0]["device_id"] == "esp32_02"

    # ID 둘 다 추출 불가 — 이벤트 미생성
    def test_no_ids_extractable_returns_empty(self):
        row = _mqtt("admin/system/control", "{broken-json")
        assert detect_mqtt_rules(row, REGISTERED) == []

    # topic_id 없고 payload_id 없음
    def test_no_topic_id_no_payload_id_returns_empty(self):
        row = _mqtt("cmd/exec", '{"temperature":25.3}')
        assert detect_mqtt_rules(row, REGISTERED) == []

    # severity 값 확인
    def test_unknown_device_severity(self):
        row = _mqtt("iot/rogue/sensor", '{"device_id":"rogue"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert events[0]["severity"] == "high"

    def test_mismatch_severity(self):
        row = _mqtt("iot/esp32_01/sensor", '{"device_id":"esp32_02"}')
        events = detect_mqtt_rules(row, REGISTERED)
        assert events[0]["severity"] == "high"

    # topic/payload 모두 미등록 — topic_id 우선
    def test_both_different_unregistered_ids_use_topic_id(self):
        row = _mqtt("iot/unknown_topic/sensor", '{"device_id":"unknown_payload"}')
        event = detect_mqtt_rules(row, REGISTERED)[0]
        assert event["event_type"] == UNKNOWN_DEVICE
        assert event["device_id"] == "unknown_topic"
