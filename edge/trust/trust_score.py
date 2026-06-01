SEVERITY_PENALTIES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 20,
    "CRITICAL": 30,
}


def apply_penalty(score: int, severity: str) -> int:
    penalty = SEVERITY_PENALTIES.get(severity, 0)
    return max(0, min(100, score - penalty))
