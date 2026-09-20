import re


def analyze_reflection(response: str, marker: str, context: str) -> dict:
    """
    Heuristic evidence scoring for reflected input.
    This does NOT prove JavaScript execution.
    """

    position = response.find(marker)

    if position == -1:
        return {
            "reflected": False,
            "raw_markup": False,
            "event_handler": False,
            "score": 0,
            "confidence": "none",
        }

    raw_markup = bool(
        re.search(
            r"<\s*/?\s*[A-Za-z][A-Za-z0-9:_-]*(?:\s|/|>|$)",
            marker,
            re.IGNORECASE,
        )
    )

    event_handler = bool(
        re.search(r"\bon[a-z]+\s*=", marker, re.IGNORECASE)
    )

    score = 1

    if context == "html-attribute":
        score += 1

    if context == "javascript":
        score += 2

    if context == "html-text+raw-markup":
        score += 2

    if raw_markup:
        score += 1

    if event_handler:
        score += 1

    score = min(score, 5)

    if score >= 4:
        confidence = "high"
    elif score >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "reflected": True,
        "raw_markup": raw_markup,
        "event_handler": event_handler,
        "score": score,
        "confidence": confidence,
        "position": position,
    }
