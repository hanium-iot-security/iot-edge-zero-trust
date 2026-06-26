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
}


def score_delta_for_event(event_type: str) -> int:
    return SCORE_DELTA_BY_EVENT.get(event_type, 0)


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
