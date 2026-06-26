from edge.trust.trust_policy import ISOLATION_THRESHOLD


def should_isolate(trust_score: int, threshold: int = ISOLATION_THRESHOLD) -> bool:
    return trust_score < threshold
