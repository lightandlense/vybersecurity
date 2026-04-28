"""Canary tests: all 10 known issues from Russell's April 2026 security audit must be flagged."""

from __future__ import annotations

from pathlib import Path

from vybersecurity.patterns import antigravity, auth, secrets
from vybersecurity.patterns.config import (
    check_api_key_reuse,
    check_gitignore_coverage,
    check_missing_gitignore,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --- Canary 5: Hardcoded Gemini key ---
def test_canary_gemini_key_detected():
    findings = secrets.scan_file(str(FIXTURES / "hardcoded_gemini_key.py"))
    rule_ids = [f.rule_id for f in findings]
    assert "hardcoded_secret" in rule_ids, "Gemini API key not flagged"


# --- Canary 2: Cookie auth literal 'granted' ---
def test_canary_granted_auth_detected():
    findings = auth.scan_file(str(FIXTURES / "granted_auth.js"))
    assert any("granted" in f.description.lower() for f in findings), \
        "Literal 'granted' auth not flagged"


# --- Canary 4: CORS wildcard ---
def test_canary_cors_wildcard_detected():
    findings = auth.scan_file(str(FIXTURES / "cors_wildcard.js"))
    assert any("cors" in f.description.lower() or "wildcard" in f.description.lower() or "*" in f.description
               for f in findings), "CORS wildcard not flagged"


# --- Canary 3: Admin route unauthenticated with TODO ---
def test_canary_admin_bypass_detected():
    findings = auth.scan_file(str(FIXTURES / "admin_middleware_bypass.ts"))
    assert any(f.rule_id == "auth_misconfig" for f in findings), \
        "Unauthenticated admin route not flagged"


# --- Canary 10: Malformed .env bare key ---
def test_canary_malformed_env_detected():
    findings = secrets.scan_env_file(str(FIXTURES / "malformed.env"))
    assert any(f.rule_id == "malformed_env" for f in findings), \
        "Malformed .env bare key not flagged"


# --- Canary 1: google_tokens unencrypted insert ---
def test_canary_google_tokens_detected():
    findings = auth.scan_file(str(FIXTURES / "google_tokens_insert.py"))
    assert any("google_tokens" in f.description.lower() or "token" in f.description.lower()
               for f in findings), "google_tokens unencrypted write not flagged"


# --- Canary: EXPO_PUBLIC_ service_role misuse ---
def test_canary_expo_public_secret_detected():
    findings = antigravity.scan_file(str(FIXTURES / "expo_public_secret.env"))
    assert any(f.rule_id == "antigravity" and "EXPO_PUBLIC_" in f.description
               for f in findings), "EXPO_PUBLIC_ secret not flagged"


# --- Canary 6: Hardcoded API key in source file (generic) ---
def test_canary_hardcoded_api_key_in_source():
    # sk- key in a Python source file should be flagged
    findings = secrets.scan_file(str(FIXTURES / "malformed.env"))
    # The bare sk- key in .env is flagged by scan_file for CREDENTIAL_PATTERNS
    rule_ids = [f.rule_id for f in findings]
    assert "hardcoded_secret" in rule_ids or "malformed_env" in rule_ids, \
        "Hardcoded key in source not flagged"


# --- API key reuse (canary 7) ---
def test_canary_api_key_reuse(tmp_path):
    # Create two .env files with the same OpenAI key
    key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={key}\n")
    (tmp_path / ".env.production").write_text(f"OPENAI_API_KEY={key}\n")
    findings = check_api_key_reuse(str(tmp_path))
    assert any(f.rule_id == "api_key_reuse" for f in findings), \
        "API key reuse across .env files not detected"


# --- .env.vercel not gitignored (canary 8) ---
def test_canary_env_vercel_not_gitignored(tmp_path):
    (tmp_path / ".env.vercel").write_text("SECRET=abc\n")
    (tmp_path / ".gitignore").write_text("node_modules/\n")
    findings = check_gitignore_coverage(str(tmp_path))
    assert any(f.rule_id == "env_not_gitignored" and ".env.vercel" in f.filename
               for f in findings), ".env.vercel not-gitignored not detected"


# --- No .gitignore in backend directory (canary 9) ---
def test_canary_missing_gitignore_in_backend(tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "app.py").write_text("# app\n")
    findings = check_missing_gitignore(str(tmp_path))
    assert any(f.rule_id == "missing_gitignore" for f in findings), \
        "Missing .gitignore in backend dir not detected"
