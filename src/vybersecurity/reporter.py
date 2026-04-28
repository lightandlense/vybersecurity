"""Output formatters: console and Markdown report."""

from __future__ import annotations

from .models import ScanResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}
SEVERITY_ICON = {"critical": "[CRITICAL]", "high": "[HIGH]", "warning": "[WARN]", "info": "[INFO]"}


def _sorted_findings(result: ScanResult):
    return sorted(result.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.filename, f.line_number))


def print_console(result: ScanResult) -> None:
    """Print findings to stdout grouped by severity."""
    findings = _sorted_findings(result)

    if not findings:
        print(f"\n[vyber-scan] Scan complete. No issues found in {result.files_scanned} files.")
        return

    counts = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n[vyber-scan] Scan of {result.target}")
    print(f"  Files scanned : {result.files_scanned}")
    print(f"  Findings      : {len(findings)} "
          f"({counts['critical']} critical, {counts['high']} high, "
          f"{counts['warning']} warning, {counts['info']} info)\n")

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
    counts = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        "# VyberSecurity Scan Report",
        "",
        f"**Target:** `{result.target}`  ",
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

    for f in findings:
        lines.append(f"### {f.severity.upper()} - {f.rule_id}")
        lines.append(f"- **File:** `{f.filename}:{f.line_number}`")
        lines.append(f"- **Description:** {f.description}")
        if f.line_content:
            lines.append(f"- **Content:** `{f.line_content}`")
        lines.append("")

    return "\n".join(lines)
