"""Trust Score policy helpers for detection events."""

from edge.detection.rule_detector import (
    ABNORMAL_PUBLISH_RATE,
    ABNORMAL_TOPIC,
    AI_ANOMALY,
    DEVICE_ID_MISMATCH,
    LARGE_PAYLOAD,
    MALFORMED_PAYLOAD,
    UNKNOWN_DEVICE,
)


PACKET_RATE_ANOMALY = "PACKET_RATE_ANOMALY"
BYTE_RATE_ANOMALY = "BYTE_RATE_ANOMALY"
BROKER_DOS_SUSPECTED = "BROKER_DOS_SUSPECTED"
NON_MQTT_TRAFFIC = "NON_MQTT_TRAFFIC"
PORT_SCAN = "PORT_SCAN"
AI_PACKET_ANOMALY = "AI_PACKET_ANOMALY"

IDENTITY = "IDENTITY"
MESSAGE_POLICY = "MESSAGE_POLICY"
FLOODING = "FLOODING"
NETWORK_POLICY = "NETWORK_POLICY"
SCAN = "SCAN"
AI_ONLY = "AI_ONLY"

MIN_TRUST_SCORE = 0
MAX_TRUST_SCORE = 100
ISOLATION_THRESHOLD = 30

NORMAL_STATUS = "normal"
WARNING_STATUS = "warning"
DANGER_STATUS = "danger"
ISOLATED_STATUS = "isolated"

SCORE_DELTA_BY_EVENT = {
    ABNORMAL_PUBLISH_RATE: -20,
    LARGE_PAYLOAD: -15,
    ABNORMAL_TOPIC: -20,
    DEVICE_ID_MISMATCH: -25,
    MALFORMED_PAYLOAD: -10,
    AI_ANOMALY: -15,
    UNKNOWN_DEVICE: 0,
    PACKET_RATE_ANOMALY: -20,
    BYTE_RATE_ANOMALY: -20,
    BROKER_DOS_SUSPECTED: -25,
    NON_MQTT_TRAFFIC: -15,
    PORT_SCAN: -20,
    AI_PACKET_ANOMALY: -15,
}

INCIDENT_FAMILY_BY_EVENT = {
    UNKNOWN_DEVICE: IDENTITY,
    DEVICE_ID_MISMATCH: IDENTITY,
    LARGE_PAYLOAD: MESSAGE_POLICY,
    MALFORMED_PAYLOAD: MESSAGE_POLICY,
    ABNORMAL_TOPIC: MESSAGE_POLICY,
    ABNORMAL_PUBLISH_RATE: FLOODING,
    PACKET_RATE_ANOMALY: FLOODING,
    BYTE_RATE_ANOMALY: FLOODING,
    BROKER_DOS_SUSPECTED: FLOODING,
    NON_MQTT_TRAFFIC: NETWORK_POLICY,
    PORT_SCAN: SCAN,
    AI_ANOMALY: AI_ONLY,
    AI_PACKET_ANOMALY: AI_ONLY,
}


def score_delta_for_event(event_type: str) -> int:
    return SCORE_DELTA_BY_EVENT.get(event_type, 0)


def has_event_policy(event_type: str) -> bool:
    return event_type in SCORE_DELTA_BY_EVENT


def require_score_delta_for_event(event_type: str) -> int:
    if event_type not in SCORE_DELTA_BY_EVENT:
        raise ValueError(f"unknown event_type policy: {event_type!r}")
    return SCORE_DELTA_BY_EVENT[event_type]


def incident_family_for_event(event_type: str) -> str | None:
    return INCIDENT_FAMILY_BY_EVENT.get(event_type)


def require_incident_family_for_event(event_type: str) -> str:
    family = incident_family_for_event(event_type)
    if family is None:
        raise ValueError(f"unknown incident family policy: {event_type!r}")
    return family


def clamp_trust_score(trust_score: int) -> int:
    return max(MIN_TRUST_SCORE, min(MAX_TRUST_SCORE, trust_score))


def apply_score_delta(trust_score: int, score_delta: int) -> int:
    return clamp_trust_score(trust_score + score_delta)


def apply_event_score_delta(trust_score: int, event_type: str) -> int:
    return apply_score_delta(trust_score, score_delta_for_event(event_type))


def status_for_trust_score(trust_score: int) -> str:
    trust_score = clamp_trust_score(trust_score)
    if trust_score >= 80:
        return NORMAL_STATUS
    if trust_score >= 60:
        return WARNING_STATUS
    if trust_score >= 30:
        return DANGER_STATUS
    return ISOLATED_STATUS


def should_isolate(trust_score: int) -> bool:
    return status_for_trust_score(trust_score) == ISOLATED_STATUS
