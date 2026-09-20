import json
from pathlib import Path


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Group logically identical findings while preserving the strongest finding."""
    groups = {}

    def strength(finding: dict) -> tuple:
        confidence_rank = {
            "high": 3,
            "medium": 2,
            "low": 1,
        }

        return (
            bool(finding.get("browser_verified")),
            confidence_rank.get(str(finding.get("confidence", "")).lower(), 0),
            float(finding.get("score", 0) or 0),
        )

    for finding in findings:
        key = (
            finding.get("url", ""),
            finding.get("parameter", ""),
            finding.get("context", ""),
            finding.get("markup_context", ""),
        )

        group = groups.setdefault(key, {})

        payload = finding.get("payload", "")
        existing = group.get(payload)

        if existing is None or strength(finding) > strength(existing):
            group[payload] = dict(finding)

    unique = []

    for payload_findings in groups.values():
        findings_by_payload = list(payload_findings.values())

        representative = dict(
            max(findings_by_payload, key=strength)
        )

        payloads = list(payload_findings.keys())
        verified_payloads = [
            payload
            for payload, finding in payload_findings.items()
            if finding.get("browser_verified")
        ]

        representative["payloads"] = payloads
        representative["payload_count"] = len(payloads)
        representative["browser_verified_count"] = len(verified_payloads)
        representative["browser_candidate_count"] = (
            len(payloads) - len(verified_payloads)
        )
        representative["browser_verified_payloads"] = verified_payloads

        if verified_payloads:
            representative["browser_verified"] = True
            representative["verification_level"] = "browser-verified"
        else:
            representative["browser_verified"] = False
            representative["verification_level"] = "reflection-candidate"

        unique.append(representative)

    return unique


def write_json(filename: str, findings: list[dict]) -> None:
    findings = dedupe_findings(findings)

    Path(filename).write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_text(filename: str, findings: list[dict]) -> None:
    findings = dedupe_findings(findings)

    lines = []

    for finding in findings:
        lines.append(
            "\n".join([
                f"URL: {finding.get('url', '')}",
                f"Result URL: {finding.get('result_url', '')}",
                f"Parameter: {finding.get('parameter', '')}",
                f"Context: {finding.get('context', '')}",
                f"Payload: {finding.get('payload', '')}",
                f"Payload count: {finding.get('payload_count', '')}",
                f"Payloads: {finding.get('payloads', [])}",
                f"Browser verified count: {finding.get('browser_verified_count', '')}",
                f"Browser candidate count: {finding.get('browser_candidate_count', '')}",
                f"Browser verified payloads: {finding.get('browser_verified_payloads', [])}",
                f"Score: {finding.get('score', '')}/5",
                f"Confidence: {finding.get('confidence', '')}",
                f"Status code: {finding.get('status_code', '')}",
                f"Content-Type: {finding.get('content_type', '')}",
                f"Final URL: {finding.get('final_url', '')}",
                f"Position: {finding.get('position', '')}",
                f"Raw markup: {finding.get('raw_markup', '')}",
                f"Event handler: {finding.get('event_handler', '')}",
                f"Reflected: {finding.get('reflected', '')}",
                f"Markup context: {finding.get('markup_context', '')}",
                f"Verification: {finding.get('verification', '')}",
                f"Browser verified: {finding.get('browser_verified', '')}",
                f"Browser started: {finding.get('browser_started', '')}",
                f"Browser page loaded: {finding.get('browser_page_loaded', '')}",
                f"Browser dialog type: {finding.get('browser_dialog_type', '')}",
                f"Browser dialog message: {finding.get('browser_dialog_message', '')}",
                f"Browser verification reason: {finding.get('browser_verification_reason', '')}",
                f"Browser error: {finding.get('browser_error', '')}",
                f"Verification level: {finding.get('verification_level', '')}",
                f"Snippet: {finding.get('snippet', '')}",
                "-" * 80,
            ])
        )

    Path(filename).write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
