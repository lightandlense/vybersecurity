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
@click.option("--quick", "mode", flag_value="quick", default=True, help="Layer 1 pattern scan only (default)")
@click.option("--full", "mode", flag_value="full", help="Layer 1 + semgrep subprocess")
@click.option("--audit", "mode", flag_value="audit", help="Full scan + write reports to .security/reports/")
@click.option(
    "--ai-triage", is_flag=True, default=False,
    help="Enable LLM triage layer (requires ANTHROPIC_API_KEY)",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output path for .md report")
@click.option("--json", "output_json", is_flag=True, default=False, help="Also write JSON report")
@click.option(
    "--fail-on", default="critical",
    type=click.Choice(["critical", "high", "warning", "info", "none"]),
    help="Exit non-zero when findings at this severity or above exist",
)
def scan(
    target: str,
    mode: str,
    ai_triage: bool,
    output: str | None,
    output_json: bool,
    fail_on: str,
) -> None:
    """Scan a project directory for security vulnerabilities."""
    from vybersecurity import reporter, scanner
    from vybersecurity.config import load

    cfg = load(target)
    result = scanner.scan(target, cfg)

    # Run LLM triage before reporting so written reports reflect triaged findings
    if ai_triage:
        from vybersecurity.triage import triage_findings
        try:
            triage = triage_findings(result)
        except EnvironmentError as exc:
            click.echo(f"[vyber-scan] {exc}", err=True)
            sys.exit(2)
        result.findings = triage.confirmed + triage.uncertain
        dismissed = len(triage.dismissed)
        click.echo(
            f"[vyber-scan] AI triage: {len(triage.confirmed)} confirmed, "
            f"{dismissed} dismissed, {len(triage.uncertain)} uncertain"
        )

    reporter.print_console(result)

    # Determine output dir
    reports_dir = Path(target) / cfg.output_dir

    if mode == "audit":
        # Auto-write both MD and JSON to .security/reports/
        reports_dir.mkdir(parents=True, exist_ok=True)
        md_path = reports_dir / "report.md"
        json_path = reports_dir / "report.json"
        md_path.write_text(reporter.to_markdown(result), encoding="utf-8")
        json_path.write_text(reporter.to_json(result), encoding="utf-8")
        click.echo(f"[vyber-scan] Reports written to {reports_dir}/")
    else:
        if output:
            out = Path(output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(reporter.to_markdown(result), encoding="utf-8")
            click.echo(f"[vyber-scan] Markdown report: {out}")
        if output_json:
            json_out = Path(output).with_suffix(".json") if output else reports_dir / "report.json"
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(reporter.to_json(result), encoding="utf-8")
            click.echo(f"[vyber-scan] JSON report: {json_out}")

    if mode == "full":
        _run_semgrep(target, reports_dir)

    # Exit code based on --fail-on
    if fail_on == "none":
        return
    severity_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    threshold = severity_order.get(fail_on, 0)
    worst = min(
        (severity_order.get(f.severity, 9) for f in result.findings),
        default=9,
    )
    if worst <= threshold:
        sys.exit(1)


def _run_semgrep(target: str, reports_dir: Path) -> None:
    """Run semgrep as a subprocess (LGPL boundary: never import as library)."""
    import shutil
    import subprocess

    if not shutil.which("semgrep"):
        click.echo("[vyber-scan] semgrep not found - skipping Layer 2. Install with: pip install semgrep")
        return

    click.echo("[vyber-scan] Running semgrep (Layer 2)...")
    reports_dir.mkdir(parents=True, exist_ok=True)
    semgrep_out = reports_dir / "semgrep.json"
    result = subprocess.run(  # noqa: S603
        ["semgrep", "--config", "auto", "--json", "-o", str(semgrep_out), target],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode not in (0, 1):
        click.echo(f"[vyber-scan] semgrep exited with code {result.returncode}")
    else:
        click.echo(f"[vyber-scan] Semgrep results written to {semgrep_out}")


if __name__ == "__main__":
    main()
