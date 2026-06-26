"""Backward-compatible Trust Score helpers."""

from edge.trust.trust_policy import (
    MAX_TRUST_SCORE,
    MIN_TRUST_SCORE,
    SCORE_DELTA_BY_EVENT,
    apply_event_score_delta,
    apply_score_delta,
    clamp_trust_score,
    score_delta_for_event,
)
