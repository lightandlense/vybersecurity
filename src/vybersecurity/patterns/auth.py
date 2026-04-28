"""Authentication and authorization pattern checks."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding
from .common import is_excluded_path, is_false_positive_line, should_ignore

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".env"}

AUTH_PATTERNS: list[tuple[str, str, str]] = [
    # Trivially forgeable string-literal auth check
    (r'===?\s*["\']granted["\']', "critical", "Auth bypass: comparing to literal 'granted' is trivially forgeable"),
    (r'===?\s*["\']true["\']', "high", "Auth check compares to string 'true' - likely a bug"),
    # JWT algorithm none
    (r'(?i)["\']alg["\']\s*:\s*["\']none["\']', "critical", "JWT: 'alg: none' bypasses signature validation"),
    (r'(?i)jwt\.sign\([^,]+,\s*["\'](?:secret|12345|test|password)["\']', "critical",
     "JWT signed with weak hardcoded secret"),
    # CORS wildcard in source code
    (r'(?i)origin\s*:\s*["\']?\*["\']?', "high", "CORS wildcard origin (*) - exposes API to any domain"),
    (r'(?i)Access-Control-Allow-Origin["\s:]+\*', "high", "CORS header set to wildcard (*)"),
    # Unauthenticated admin route with TODO (same line or nearby)
    (r'(?i)/admin.*(?:todo|fixme|hack)', "critical", "Admin route marked TODO/FIXME - likely unauthenticated"),
    (r'(?i)(?:todo|fixme).*["\']?/admin', "critical", "Admin route marked TODO/FIXME - likely unauthenticated"),
    # Middleware bypass patterns: admin path in matcher/exclusion list
    (r'(?i)(?:matcher|exclude|bypass|skip).*[/\\]admin', "high", "Admin route excluded from middleware - verify auth"),
    # Supabase service_role exposed to client
    (r'(?i)NEXT_PUBLIC_SUPABASE_SERVICE_ROLE', "critical",
     "Supabase service_role key exposed to client via NEXT_PUBLIC_ prefix"),
    (r'(?i)supabase_service_role.*=\s*["\'][^"\']+["\']', "critical", "Supabase service_role key hardcoded"),
    # Overly permissive RLS
    (r'(?i)create\s+policy.*using\s*\(\s*true\s*\)', "warning", "Supabase RLS policy with USING (true) - allows all"),
    # Unencrypted refresh token storage hint (table name anywhere on the line)
    (r'(?i)google_tokens', "high",
     "Reference to google_tokens table - ensure OAuth tokens are encrypted at rest"),
    # NextAuth weak secret
    (r'(?i)NEXTAUTH_SECRET\s*=\s*["\'](?:secret|test|12345)["\']', "critical", "NextAuth weak hardcoded secret"),
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

        for pattern, severity, desc in AUTH_PATTERNS:
            if re.search(pattern, line):
                if should_ignore(line, "auth_misconfig"):
                    continue
                findings.append(Finding(
                    rule_id="auth_misconfig",
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
