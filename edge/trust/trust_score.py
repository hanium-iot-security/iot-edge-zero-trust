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

SCORE_DELTA_BY_EVENT = {
    DEVICE_ID_MISMATCH: -25,
    ABNORMAL_PUBLISH_RATE: -20,
    ABNORMAL_TOPIC: -20,
    LARGE_PAYLOAD: -15,
    AI_ANOMALY: -15,
    MALFORMED_PAYLOAD: -10,
    UNKNOWN_DEVICE: 0,
}


def score_delta_for_event(event_type: str) -> int:
    return SCORE_DELTA_BY_EVENT.get(event_type, 0)


def apply_score_delta(score: int, score_delta: int) -> int:
    return max(MIN_TRUST_SCORE, min(MAX_TRUST_SCORE, score + score_delta))


def apply_event_score_delta(score: int, event_type: str) -> int:
    return apply_score_delta(score, score_delta_for_event(event_type))
