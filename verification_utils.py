def verify_reflection(response: str, payload: str, context: str) -> dict:
    """
    Heuristic verification.

    This verifies that the exact payload is reflected and records
    the observed context. It does not execute JavaScript and does
    not prove browser-side XSS.
    """

    reflected = payload in response

    markup_contexts = {
        "html-text+raw-markup",
        "html-tag",
        "html-attribute",
        "javascript",
    }

    markup_relevant = context in markup_contexts

    if not reflected:
        status = "not-reflected"
    elif markup_relevant:
        status = "reflected-in-executable-context-candidate"
    else:
        status = "reflected"

    return {
        "reflected": reflected,
        "markup_context": markup_relevant,
        "verification": status,
    }
