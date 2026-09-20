def classify_risk(
    browser_verified: bool,
    score,
    confidence: str,
    event_handler: bool,
    raw_markup: bool,
) -> dict:
    """Classify finding risk from available XSS evidence."""
    try:
        score = float(score or 0)
    except (TypeError, ValueError):
        score = 0

    confidence = str(confidence or "").lower()

    if browser_verified:
        return {
            "risk_level": "High",
            "risk_reason": "Chromium confirmed browser-side JavaScript execution",
        }

    if (
        confidence == "high"
        and score >= 4
        and (event_handler or raw_markup)
    ):
        return {
            "risk_level": "Medium",
            "risk_reason": "Strong executable-context XSS candidate without browser confirmation",
        }

    if confidence in {"high", "medium"} and score >= 3:
        return {
            "risk_level": "Low",
            "risk_reason": "Reflection detected with limited execution evidence",
        }

    return {
        "risk_level": "Low",
        "risk_reason": "Weak reflection evidence",
    }
