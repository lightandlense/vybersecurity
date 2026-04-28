"""Output formatters: console, Markdown, and JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import ScanResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}
SEVERITY_ICON = {"critical": "[CRITICAL]", "high": "[HIGH]", "warning": "[WARN]", "info": "[INFO]"}


def _sorted_findings(result: ScanResult):
    return sorted(
        result.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.filename, f.line_number),
    )


def _counts(result: ScanResult) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def print_console(result: ScanResult) -> None:
    """Print findings to stdout grouped by severity."""
    findings = _sorted_findings(result)

    if not findings:
        print(f"\n[vyber-scan] Scan complete. No issues found in {result.files_scanned} files.")
        return

    counts = _counts(result)
    print(f"\n[vyber-scan] Scan of {result.target}")
    print(f"  Files scanned : {result.files_scanned}")
    print(
        f"  Findings      : {len(findings)} "
        f"({counts['critical']} critical, {counts['high']} high, "
        f"{counts['warning']} warning, {counts['info']} info)\n"
    )

    for f in findings:
        icon = SEVERITY_ICON.get(f.severity, "[?]")
        print(f"  {icon} {f.filename}:{f.line_number}")
        print(f"         Rule    : {f.rule_id}")
        print(f"         Detail  : {f.description}")
        if f.line_content:
            print(f"         Content : {f.line_content}")
        print()


def to_markdown(result: ScanResult) -> str:
    """Render findings as a Markdown report."""
    findings = _sorted_findings(result)
    counts = _counts(result)
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# VyberSecurity Scan Report",
        "",
        f"**Target:** `{result.target}`  ",
        f"**Scanned:** {ts}  ",
        f"**Files scanned:** {result.files_scanned}  ",
        f"**Total findings:** {len(findings)} "
        f"({counts['critical']} critical, {counts['high']} high, "
        f"{counts['warning']} warning, {counts['info']} info)",
        "",
    ]

    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")

    current_severity = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            lines.append(f"### {f.severity.upper()}")
            lines.append("")
        lines.append(f"**{f.rule_id}** - `{f.filename}:{f.line_number}`")
        lines.append(f"> {f.description}")
        if f.line_content:
            lines.append(f"```\n{f.line_content}\n```")
        lines.append("")

    return "\n".join(lines)


def to_json(result: ScanResult) -> str:
    """Render findings as JSON."""
    findings = _sorted_findings(result)
    counts = _counts(result)
    return json.dumps(
        {
            "target": result.target,
            "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
            "files_scanned": result.files_scanned,
            "summary": counts,
            "findings": [f.model_dump() for f in findings],
        },
        indent=2,
    )
