"""MVP용 rule-based MQTT 이상 탐지 상수 및 순수 판정 함수."""

from typing import Any

from edge.features.feature_utils import extract_payload_device_id
from edge.mqtt.topic_utils import extract_device_id_candidate_from_topic

DETECTOR_RULE = "RULE"
DETECTOR_AI = "AI"

ABNORMAL_PUBLISH_RATE = "ABNORMAL_PUBLISH_RATE"
LARGE_PAYLOAD = "LARGE_PAYLOAD"
MALFORMED_PAYLOAD = "MALFORMED_PAYLOAD"
ABNORMAL_TOPIC = "ABNORMAL_TOPIC"
UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
DEVICE_ID_MISMATCH = "DEVICE_ID_MISMATCH"
AI_ANOMALY = "AI_ANOMALY"

RULE_EVENT_TYPES = {
    ABNORMAL_PUBLISH_RATE,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    ABNORMAL_TOPIC,
    UNKNOWN_DEVICE,
    DEVICE_ID_MISMATCH,
}

AI_EVENT_TYPES = {AI_ANOMALY}

PUBLISH_COUNT_THRESHOLD = 15
LARGE_PAYLOAD_BYTES = 5120
MALFORMED_PAYLOAD_THRESHOLD = 3
ABNORMAL_TOPIC_THRESHOLD = 3

ISOLATION_FOREST_FEATURES = (
    "publish_count",
    "avg_payload_size",
    "max_payload_size",
    "avg_message_interval",
    "min_message_interval",
)

_FEATURE_SEVERITY = {
    ABNORMAL_PUBLISH_RATE: "high",
    LARGE_PAYLOAD: "medium",
    MALFORMED_PAYLOAD: "medium",
    ABNORMAL_TOPIC: "high",
}

_MQTT_SEVERITY = {
    UNKNOWN_DEVICE: "high",
    DEVICE_ID_MISMATCH: "high",
}


def detect_feature_rules(feature_row: dict[str, Any]) -> list[dict[str, Any]]:
    """feature_logs row에서 Rule 이벤트 목록을 반환합니다. DB 접근 없음."""
    events: list[dict[str, Any]] = []

    if int(feature_row["publish_count"]) > PUBLISH_COUNT_THRESHOLD:
        events.append({"event_type": ABNORMAL_PUBLISH_RATE, "severity": _FEATURE_SEVERITY[ABNORMAL_PUBLISH_RATE]})

    if int(feature_row["max_payload_size"]) > LARGE_PAYLOAD_BYTES:
        events.append({"event_type": LARGE_PAYLOAD, "severity": _FEATURE_SEVERITY[LARGE_PAYLOAD]})

    if int(feature_row["malformed_payload_count"]) >= MALFORMED_PAYLOAD_THRESHOLD:
        events.append({"event_type": MALFORMED_PAYLOAD, "severity": _FEATURE_SEVERITY[MALFORMED_PAYLOAD]})

    if int(feature_row["abnormal_topic_count"]) >= ABNORMAL_TOPIC_THRESHOLD:
        events.append({"event_type": ABNORMAL_TOPIC, "severity": _FEATURE_SEVERITY[ABNORMAL_TOPIC]})

    return events


def detect_mqtt_rules(
    mqtt_row: dict[str, Any],
    registered_devices: set[str],
) -> list[dict[str, Any]]:
    """mqtt_logs row에서 Rule 이벤트 목록을 반환합니다. DB 접근 없음.

    판정 우선순위:
    1. topic_id / payload_id 중 하나라도 미등록 → UNKNOWN_DEVICE
    2. 둘 다 등록 기기이지만 서로 다름 → DEVICE_ID_MISMATCH
    3. 둘 다 추출 불가 → 이벤트 미생성
    """
    topic_id = extract_device_id_candidate_from_topic(mqtt_row["topic"])
    payload_id = extract_payload_device_id(mqtt_row["payload"])

    if topic_id is None and payload_id is None:
        return []

    topic_registered = topic_id in registered_devices if topic_id else None
    payload_registered = payload_id in registered_devices if payload_id else None

    if topic_registered is False or payload_registered is False:
        unregistered_id = (topic_id if topic_registered is False else payload_id)
        return [{
            "event_type": UNKNOWN_DEVICE,
            "severity": _MQTT_SEVERITY[UNKNOWN_DEVICE],
            "device_id": unregistered_id,
            "topic_id": topic_id,
            "payload_id": payload_id,
        }]

    if topic_id and payload_id and topic_id != payload_id:
        return [{
            "event_type": DEVICE_ID_MISMATCH,
            "severity": _MQTT_SEVERITY[DEVICE_ID_MISMATCH],
            "device_id": topic_id,
            "topic_id": topic_id,
            "payload_id": payload_id,
        }]

    return []
