def severity_from_alert_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"

    return "low"


def severity_from_container_risk(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"

    return "low"


def severity_from_z_score(max_z_score: float) -> str:
    if max_z_score >= 10:
        return "high"
    if max_z_score >= 5:
        return "medium"

    return "low"


def severity_from_lof(lof_value: float) -> str:
    if lof_value >= 10:
        return "high"
    if lof_value >= 3:
        return "medium"

    return "low"