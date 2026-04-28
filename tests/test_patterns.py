"""Unit tests for individual pattern modules."""

from __future__ import annotations

from vybersecurity.patterns import auth, secrets
from vybersecurity.patterns.common import entropy, should_ignore


# --- common ---
def test_entropy_high_for_random_string():
    assert entropy("aBcD1234!@#$efgh") > 3.5


def test_entropy_low_for_repeated():
    assert entropy("aaaaaaaaaa") < 1.0


def test_should_ignore_blanket():
    assert should_ignore("const key = 'abc'  # vyber-ignore", "hardcoded_secret")


def test_should_ignore_specific_rule():
    assert should_ignore("const key = 'abc'  # vyber-ignore:hardcoded_secret", "hardcoded_secret")


def test_should_ignore_does_not_ignore_other_rule():
    assert not should_ignore("const key = 'abc'  # vyber-ignore:auth_misconfig", "hardcoded_secret")


# --- secrets ---
def test_openai_key_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('OPENAI_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    findings = secrets.scan_file(str(f))
    assert any(find.rule_id == "hardcoded_secret" for find in findings)


def test_anthropic_key_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('key = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12"\n')
    findings = secrets.scan_file(str(f))
    assert any(find.rule_id == "hardcoded_secret" for find in findings)


def test_telegram_bot_token_in_source(tmp_path):
    f = tmp_path / "bot.py"
    f.write_text('TOKEN = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"\n')
    findings = secrets.scan_file(str(f))
    assert any(find.rule_id == "hardcoded_secret" for find in findings)


def test_placeholder_key_not_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('OPENAI_KEY = "your_api_key_here"\n')
    findings = secrets.scan_file(str(f))
    assert not any(find.rule_id == "hardcoded_secret" for find in findings)


def test_comment_line_skipped(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('# OPENAI_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
    findings = secrets.scan_file(str(f))
    assert not any(find.rule_id == "hardcoded_secret" for find in findings)


# --- auth ---
def test_granted_string_flagged(tmp_path):
    f = tmp_path / "auth.js"
    f.write_text('if (cookie === "granted") { return true; }\n')
    findings = auth.scan_file(str(f))
    assert any(find.rule_id == "auth_misconfig" for find in findings)


def test_cors_wildcard_flagged(tmp_path):
    f = tmp_path / "server.js"
    f.write_text('app.use(cors({ origin: "*" }));\n')
    findings = auth.scan_file(str(f))
    assert any(find.rule_id == "auth_misconfig" for find in findings)


def test_next_public_service_role_flagged(tmp_path):
    f = tmp_path / ".env"
    f.write_text("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE=eyJhbGciOiJIUzI1NiJ9.payload.sig\n")
    findings = auth.scan_file(str(f))
    assert any(find.rule_id == "auth_misconfig" for find in findings)
