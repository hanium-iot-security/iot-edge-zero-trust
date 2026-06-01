def should_isolate(trust_score: int, threshold: int = 30) -> bool:
    return trust_score < threshold
