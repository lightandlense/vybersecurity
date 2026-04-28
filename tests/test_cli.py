"""CLI smoke tests."""

from click.testing import CliRunner

from vybersecurity.cli import main


def test_help_exits_zero():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "vyber-scan" in result.output or "VyberSecurity" in result.output


def test_scan_help():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--quick" in result.output
    assert "--full" in result.output
    assert "--ai-triage" in result.output
