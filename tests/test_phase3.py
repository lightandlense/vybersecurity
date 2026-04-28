"""Phase 3: runner CLI, JSON/MD output, config file, vyber-ignore suppression."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from vybersecurity import reporter, scanner
from vybersecurity.cli import main
from vybersecurity.config import VyberConfig, load

FIXTURES = Path(__file__).parent / "fixtures"


# --- Config loading ---
def test_config_defaults_when_no_file(tmp_path):
    cfg = load(str(tmp_path))
    assert cfg.severity_threshold == "info"
    assert "secrets" in cfg.enabled_modules


def test_config_loads_from_yml(tmp_path):
    (tmp_path / ".vybersecurity.yml").write_text(
        "severity_threshold: high\noutput_dir: custom/reports\n"
    )
    cfg = load(str(tmp_path))
    assert cfg.severity_threshold == "high"
    assert cfg.output_dir == "custom/reports"


def test_config_invalid_yml_returns_defaults(tmp_path):
    (tmp_path / ".vybersecurity.yml").write_text(":[invalid yaml")
    cfg = load(str(tmp_path))
    assert cfg.severity_threshold == "info"


# --- JSON output ---
def test_json_output_is_valid(tmp_path):
    (tmp_path / "app.py").write_text('API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"\n')
    result = scanner.scan(str(tmp_path))
    output = reporter.to_json(result)
    data = json.loads(output)
    assert "findings" in data
    assert "summary" in data
    assert data["files_scanned"] > 0


def test_json_findings_have_required_fields(tmp_path):
    (tmp_path / "app.py").write_text('API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"\n')
    result = scanner.scan(str(tmp_path))
    output = reporter.to_json(result)
    data = json.loads(output)
    for finding in data["findings"]:
        assert "rule_id" in finding
        assert "severity" in finding
        assert "filename" in finding
        assert "line_number" in finding
        assert "description" in finding


# --- Markdown output ---
def test_markdown_contains_target(tmp_path):
    result = scanner.scan(str(tmp_path))
    md = reporter.to_markdown(result)
    assert str(tmp_path) in md


def test_markdown_no_findings_message(tmp_path):
    (tmp_path / "clean.py").write_text("print('hello')\n")
    result = scanner.scan(str(tmp_path))
    if not result.findings:
        md = reporter.to_markdown(result)
        assert "No issues found" in md


# --- CLI scan command ---
def test_cli_scan_quick(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--quick", "--fail-on", "none"])
    assert result.exit_code == 0
    assert "vyber-scan" in result.output


def test_cli_scan_writes_markdown(tmp_path):
    (tmp_path / "app.js").write_text('const key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";\n')
    out = tmp_path / "report.md"
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--output", str(out), "--fail-on", "none"])
    assert result.exit_code == 0
    assert out.exists()
    content = out.read_text()
    assert "VyberSecurity" in content


def test_cli_scan_writes_json(tmp_path):
    (tmp_path / "app.js").write_text('const key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";\n')
    out = tmp_path / "report.md"
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--output", str(out), "--json", "--fail-on", "none"]
    )
    assert result.exit_code == 0
    json_out = out.with_suffix(".json")
    assert json_out.exists()
    data = json.loads(json_out.read_text())
    assert "findings" in data


def test_cli_audit_writes_to_security_dir(tmp_path):
    (tmp_path / "app.py").write_text('TOKEN = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--audit", "--fail-on", "none"])
    assert result.exit_code == 0
    reports_dir = tmp_path / ".security" / "reports"
    assert (reports_dir / "report.md").exists()
    assert (reports_dir / "report.json").exists()


def test_cli_exits_nonzero_on_critical(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_cli_exits_zero_with_fail_on_none(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == 0


# --- vyber-ignore suppression ---
def test_vyber_ignore_suppresses_finding(tmp_path):
    (tmp_path / "app.py").write_text(
        'KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"  # vyber-ignore\n'
    )
    from vybersecurity.patterns import secrets
    findings = secrets.scan_file(str(tmp_path / "app.py"))
    assert not any(f.rule_id == "hardcoded_secret" for f in findings)


def test_vyber_ignore_specific_rule(tmp_path):
    (tmp_path / "app.py").write_text(
        'KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"  # vyber-ignore:hardcoded_secret\n'
    )
    from vybersecurity.patterns import secrets
    findings = secrets.scan_file(str(tmp_path / "app.py"))
    assert not any(f.rule_id == "hardcoded_secret" for f in findings)


def test_vyber_ignore_wrong_rule_does_not_suppress(tmp_path):
    (tmp_path / "app.py").write_text(
        'KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"  # vyber-ignore:auth_misconfig\n'
    )
    from vybersecurity.patterns import secrets
    findings = secrets.scan_file(str(tmp_path / "app.py"))
    assert any(f.rule_id == "hardcoded_secret" for f in findings)


# --- Config: disabled modules ---
def test_disabled_module_skips_scanning(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    cfg = VyberConfig(enabled_modules=["auth"])  # secrets disabled
    result = scanner.scan(str(tmp_path), cfg)
    assert not any(f.rule_id == "hardcoded_secret" for f in result.findings)


# --- Config: severity threshold ---
def test_severity_threshold_filters_low(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    cfg = VyberConfig(severity_threshold="critical")
    result = scanner.scan(str(tmp_path), cfg)
    assert all(f.severity == "critical" for f in result.findings)
