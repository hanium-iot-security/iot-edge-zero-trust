STATUS_VALUES = ("normal", "warning", "danger", "isolated")


def status_for_trust_score(trust_score: int) -> str:
    if trust_score >= 80:
        return "normal"
    if trust_score >= 60:
        return "warning"
    if trust_score >= 30:
        return "danger"
    return "isolated"
