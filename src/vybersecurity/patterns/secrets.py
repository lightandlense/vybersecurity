"""Hardcoded secrets detection - ported and extended from Vibe-Guard (MIT)."""

from __future__ import annotations

import re

from ..models import Finding
from .common import entropy, is_false_positive_line, should_ignore, walk_files

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".yml", ".yaml", ".json", ".sh"}

# (pattern, severity, description)
CREDENTIAL_PATTERNS: list[tuple[str, str, str]] = [
    # OpenAI
    (r"sk-[a-zA-Z0-9]{32,}", "critical", "OpenAI API key"),
    (r"sk-proj-[a-zA-Z0-9_-]{40,}", "critical", "OpenAI project API key"),
    # Anthropic
    (r"sk-ant-[a-zA-Z0-9_-]{40,}", "critical", "Anthropic API key"),
    # Google / GCP / Gemini
    (r"AIza[0-9A-Za-z\-_]{35}", "critical", "Google/Gemini API key (GCP)"),
    (r"ya29\.[0-9a-zA-Z\-_]+", "critical", "Google OAuth access token"),
    # GitHub
    (r"ghp_[a-zA-Z0-9]{36}", "critical", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "critical", "GitHub OAuth Token"),
    # Slack
    (r"xoxb-[a-zA-Z0-9\-]{50,}", "critical", "Slack Bot Token"),
    # Stripe
    (r"(sk_live|rk_live)_[a-zA-Z0-9]{24,}", "critical", "Stripe Secret Key"),
    # SendGrid
    (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "critical", "SendGrid API Key"),
    # AWS
    (r'(?i)aws_secret_access_key\s*=\s*["\']?([a-zA-Z0-9/+]{40})["\']?', "critical", "AWS Secret Access Key"),
    # Telegram bot token
    (r"\d{8,10}:[A-Za-z0-9_-]{35}", "critical", "Telegram Bot Token"),
    # Generic API key assignment in source code
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "critical", "Hardcoded API key"),
    # Generic password/secret in source code (not .env)
    (r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']{8,})["\']', "high", "Hardcoded password"),
    (r'(?i)(secret|token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "high", "Hardcoded secret/token"),
    # MongoDB URI with creds
    (r'mongodb(?:\+srv)?://[^:]+:[^@]+@[a-zA-Z0-9.\-]+', "critical", "MongoDB URI with credentials"),
]


def scan_file(filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//")):
            continue
        if is_false_positive_line(line):
            continue

        for pattern, severity, desc in CREDENTIAL_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "hardcoded_secret"):
                    continue
                findings.append(Finding(
                    rule_id="hardcoded_secret",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:120],
                    description=desc,
                ))
                break

        # High-entropy string detection (catch keys that don't match known patterns)
        for token in re.findall(r'["\']([a-zA-Z0-9+/=_\-]{20,})["\']', line):
            if entropy(token) > 4.5:
                if should_ignore(line, "high_entropy"):
                    continue
                findings.append(Finding(
                    rule_id="high_entropy",
                    severity="warning",
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:120],
                    description=f"High-entropy string (entropy={entropy(token):.2f}) - possible secret",
                ))
                break

    return findings


def scan_env_file(filepath: str) -> list[Finding]:
    """Scan .env files for malformed entries (bare keys without variable names)."""
    findings: list[Finding] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Malformed .env: line that looks like a key value but has no VAR= prefix
        if "=" not in stripped:
            # Check if it looks like a credential (high entropy, long alphanumeric)
            tokens = re.findall(r"([a-zA-Z0-9_\-]{20,})", stripped)
            for token in tokens:
                if entropy(token) > 4.0:
                    findings.append(Finding(
                        rule_id="malformed_env",
                        severity="high",
                        filename=filepath,
                        line_number=i,
                        line_content=stripped[:60] + "...",
                        description="Malformed .env entry: credential value with no variable name",
                    ))
                    break

    return findings


def scan_directory(path: str) -> list[Finding]:
    findings: list[Finding] = []
    for p in walk_files(path):
        name = p.name.lower()
        if p.suffix in SCAN_EXTENSIONS:
            findings.extend(scan_file(str(p)))
        if name.startswith(".env"):
            findings.extend(scan_env_file(str(p)))
    return findings
