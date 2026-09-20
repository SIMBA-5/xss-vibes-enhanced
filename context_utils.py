import re


def detect_context(response: str, marker: str) -> str:
    """
    Heuristic reflection-context classifier.

    This classifies where the reflected marker appears.
    It does not by itself prove exploitability.
    """

    pos = response.find(marker)

    if pos == -1:
        return "not-reflected"

    before = response[:pos]

    # HTML comment
    last_open_comment = before.rfind("<!--")
    last_close_comment = before.rfind("-->")

    if last_open_comment > last_close_comment:
        return "html-comment"

    # JavaScript block
    last_script_open = before.lower().rfind("<script")
    last_script_close = before.lower().rfind("</script")

    if last_script_open > last_script_close:
        return "javascript"

    # Determine whether the marker itself contains raw HTML markup.
    raw_markup = bool(
        re.search(r"<\s*/?\s*[A-Za-z][A-Za-z0-9:_-]*(?:\s|/?>|$)",
                  marker,
                  re.IGNORECASE)
    )

    raw_event_handler = bool(
        re.search(r"\bon[a-z]+\s*=", marker, re.IGNORECASE)
    )

    # Inside an HTML tag / attribute
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")

    if last_lt > last_gt:
        fragment = before[last_lt:]

        if re.search(r'=\s*["\'][^"\']*$', fragment):
            return "html-attribute"

        if re.search(r'=\s*[^\s>]*$', fragment):
            return "html-attribute"

        return "html-tag"

    # Marker is in normal HTML text but contains raw active markup.
    if raw_markup or raw_event_handler:
        return "html-text+raw-markup"

    return "html-text"
