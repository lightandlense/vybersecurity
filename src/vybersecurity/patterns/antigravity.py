"""Antigravity/Russell stack-specific patterns not covered by generic scanners."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding
from .common import is_excluded_path, should_ignore

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".yml", ".yaml"}

ANTIGRAVITY_PATTERNS: list[tuple[str, str, str]] = [
    # Telegram bot token in source (not .env)
    (r"\d{8,10}:[A-Za-z0-9_-]{35}", "critical", "Telegram Bot Token exposed in source file"),
    # Expo EXPO_PUBLIC_ prefix misuse for backend secrets
    (r"EXPO_PUBLIC_(?:SUPABASE_SERVICE_ROLE|SECRET|API_KEY|PRIVATE|TOKEN)", "critical",
     "Backend secret exposed via EXPO_PUBLIC_ prefix - visible to all app users"),
    # Supabase service_role behind NEXT_PUBLIC
    (r"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE", "critical",
     "Supabase service_role key exposed to browser via NEXT_PUBLIC_ prefix"),
    # Webhook without HMAC verification
    (r'(?i)def.*webhook.*\(|app\.(post|put)\s*\(["\'][^"\']*webhook', "info",
     "Webhook endpoint detected - verify HMAC signature validation is present"),
    # .env path hardcoded to agent-specific location (Telegram per-agent config leak)
    (r'(?i)\.claude[/\\]telegram[/\\]\.env', "warning",
     "Hardcoded path to per-agent Telegram .env - config path leak"),
    # CORS wildcard in Python (FastAPI/Flask)
    (r'(?i)allow_origins\s*=\s*\[\s*["\']?\*["\']?\s*\]', "high",
     "FastAPI/Starlette CORS: allow_origins=['*'] exposes API to any domain"),
    # Google refresh token table unencrypted write
    (r'(?i)(?:insert|upsert|update).*(?:refresh_token|access_token).*google_tokens', "high",
     "Possible unencrypted OAuth token written to google_tokens table"),
    # Admin route middleware bypass
    (r'''(?i)['"][/\\]admin['"]''', "info",
     "Admin route reference - verify authentication middleware covers this path"),
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

        for pattern, severity, desc in ANTIGRAVITY_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "antigravity"):
                    continue
                findings.append(Finding(
                    rule_id="antigravity",
                    severity=severity,
                    filename=filepath,
                    line_number=i,
                    line_content=stripped[:120],
                    description=desc,
                ))

    return findings


def scan_directory(path: str) -> list[Finding]:
    findings: list[Finding] = []
    for p in Path(path).rglob("*"):
        if not p.is_file() or is_excluded_path(str(p)):
            continue
        if p.suffix in SCAN_EXTENSIONS or p.name.lower().startswith(".env"):
            findings.extend(scan_file(str(p)))
    return findings
