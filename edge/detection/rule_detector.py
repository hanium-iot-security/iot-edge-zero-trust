"""MVP용 rule-based MQTT 이상 탐지 상수 및 순수 판정 함수."""

from typing import Any

from edge.mqtt.identity import IdentityStatus, classify_mqtt_identity

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

    Topic Device ID·Payload Device ID·등록 Device 여부 판정 자체는
    `edge.mqtt.identity.classify_mqtt_identity`(공통 Helper) 한 곳에서만
    수행하며, 이 함수는 그 판정 결과를 Rule Event 형태로 변환하기만 한다.

    판정 우선순위(공통 모듈 계약):
    1. topic_id / payload_id 중 하나라도 미등록 → UNKNOWN_DEVICE
    2. 둘 다 등록 기기이지만 서로 다름 → DEVICE_ID_MISMATCH
    3. 둘 다 추출 불가, 또는 정상 판정(MATCHED) → 이벤트 미생성
    """
    identity = classify_mqtt_identity(
        mqtt_row["topic"], mqtt_row["payload"], registered_devices
    )

    if identity.status is IdentityStatus.UNKNOWN_DEVICE:
        return [{
            "event_type": UNKNOWN_DEVICE,
            "severity": _MQTT_SEVERITY[UNKNOWN_DEVICE],
            "device_id": identity.unregistered_device_id,
            "topic_id": identity.topic_device_id,
            "payload_id": identity.payload_device_id,
        }]

    if identity.status is IdentityStatus.DEVICE_ID_MISMATCH:
        return [{
            "event_type": DEVICE_ID_MISMATCH,
            "severity": _MQTT_SEVERITY[DEVICE_ID_MISMATCH],
            "device_id": identity.topic_device_id,
            "topic_id": identity.topic_device_id,
            "payload_id": identity.payload_device_id,
        }]

    return []