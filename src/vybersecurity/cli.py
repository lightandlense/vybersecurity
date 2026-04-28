"""VyberSecurity CLI entry point."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from vybersecurity import __version__


@click.group()
@click.version_option(version=__version__, prog_name="vyber-scan")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging")
def main(verbose: bool) -> None:
    """VyberSecurity - security scanner for vibe-coded projects.

    Catches AI-generated code vulnerabilities before they ship.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--quick", "mode", flag_value="quick", default=True, help="Fast pattern scan only (default)"
)
@click.option("--full", "mode", flag_value="full", help="Pattern scan + semgrep")
@click.option("--audit", "mode", flag_value="audit", help="Full scan + report")
@click.option(
    "--ai-triage", is_flag=True, default=False,
    help="Enable LLM triage layer (requires ANTHROPIC_API_KEY)",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output report path (.md)")
@click.option("--fail-on", default="critical", help="Exit non-zero if findings at this severity or above")
def scan(
    target: str,
    mode: str,
    ai_triage: bool,
    output: str | None,
    fail_on: str,
) -> None:
    """Scan a project directory for security vulnerabilities."""
    from vybersecurity import reporter, scanner

    result = scanner.scan(target)
    reporter.print_console(result)

    if output:
        report_path = Path(output)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(reporter.to_markdown(result), encoding="utf-8")
        click.echo(f"[vyber-scan] Report written to {report_path}")

    severity_levels = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    threshold = severity_levels.get(fail_on, 0)
    worst = min(
        (severity_levels.get(f.severity, 9) for f in result.findings),
        default=9,
    )
    if worst <= threshold:
        sys.exit(1)


if __name__ == "__main__":
    main()
