"""VyberSecurity CLI entry point."""

from __future__ import annotations

import click

from vybersecurity import __version__


@click.group()
@click.version_option(version=__version__, prog_name="vyber-scan")
def main() -> None:
    """VyberSecurity - security scanner for vibe-coded projects.

    Catches AI-generated code vulnerabilities before they ship.
    """


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
@click.option("--output", "-o", type=click.Path(), default=None, help="Output report path")
def scan(target: str, mode: str, ai_triage: bool, output: str | None) -> None:
    """Scan a project directory for security vulnerabilities."""
    click.echo(f"[vyber-scan] Scanning {target} (mode={mode}, ai-triage={ai_triage})")
    click.echo("[vyber-scan] Pattern layer: not yet implemented (Phase 2)")


if __name__ == "__main__":
    main()
