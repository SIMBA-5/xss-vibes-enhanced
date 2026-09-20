import json
from pathlib import Path


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings while preserving discovery order."""
    unique = []
    seen = set()

    for finding in findings:
        key = (
            finding.get("url", ""),
            finding.get("parameter", ""),
            finding.get("payload", ""),
            finding.get("context", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

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
                f"Snippet: {finding.get('snippet', '')}",
                "-" * 80,
            ])
        )

    Path(filename).write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
