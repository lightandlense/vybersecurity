# VyberSecurity

[![CI](https://github.com/lightandlense/vybersecurity/actions/workflows/security.yml/badge.svg)](https://github.com/lightandlense/vybersecurity/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Security scanner for vibe-coded projects.** Catches AI-generated code vulnerabilities before they ship.

> 91.5% of vibe-coded apps in Q1 2026 had at least one AI-hallucination vulnerability. AI-assisted code has 2.74x the flaw rate of human-written code. Generic scanners miss most of it because they don't know what to look for.

VyberSecurity is built for the way AI tools actually generate code. It catches the failure modes that show up when an LLM writes a Next.js API route, a Supabase RLS policy, a Stripe webhook handler, or an Expo app, and the developer doesn't know what they don't know.

## What it finds

VyberSecurity ships with rules grounded in OWASP Top 10:2025, OWASP LLM Top 10, OWASP Agentic AI 2026, the CWE Top 25, and real breach postmortems. It catches:

**Hardcoded secrets that LLMs love to inline**
- OpenAI, Anthropic, Google, GitHub, Slack, Stripe, SendGrid, AWS, Telegram credentials
- MongoDB URIs with embedded passwords
- Generic API keys, passwords, tokens

**Auth and authorization failures**
- JWT `alg: none` bypass
- JWT signed with hardcoded weak secrets
- Auth checks comparing to literal `"granted"` or `"true"`
- CORS wildcard origins
- Admin routes marked TODO/FIXME
- Middleware exclusions that strand admin paths
- Supabase RLS policies with `USING (true)`
- NextAuth weak secrets

**AI-stack-specific traps**
- `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE` (the most common Next.js vibe-code disaster)
- `EXPO_PUBLIC_` prefix misuse for backend secrets in React Native apps
- Webhooks missing HMAC signature validation
- FastAPI / Starlette `allow_origins=['*']`
- Unencrypted OAuth refresh tokens in database

Run `vyber-scan` against your codebase and you get prioritized findings with file path, line number, and an actionable description, not a 200-page audit.

## How it works, 4-layer pipeline

Each layer adds time but reduces noise. Run only Layer 1 on every commit. Layer 2 through 4 on demand.

```
your code
    │
    ▼
Layer 1 — Pattern scan      (seconds)
  • Hardcoded secrets, auth bugs, config errors
  • Stack-specific rules (Next.js, Expo, Supabase, Stripe)
    │
    ▼
Layer 2 — Semgrep            (~30s, optional)
  • Subprocess only, never linked as a library
  • Pulls semgrep's curated rule pack
    │
    ▼
Layer 3 — AI Triage          (~1-2 min, optional)
  • Claude Sonnet classifies each finding: confirmed / dismissed / uncertain
  • Suppresses known-and-accepted findings via .vybersecurity.yml
  • Cuts noise so reviewers only see actionable issues
    │
    ▼
Layer 4 — DAST + STRIDE      (on demand)
  • Runtime web testing for vulns that pattern scans cannot find
  • STRIDE threat model generation for new features
```

Layer 1 is the default. Each next layer is opt-in via a flag.

## Install

From source. PyPI release coming soon.

```bash
git clone https://github.com/lightandlense/vybersecurity
cd vybersecurity
pip install -e ".[dev]"
```

Requires Python 3.10+. Optional: `pip install semgrep` to enable Layer 2.

## Usage

```bash
# Layer 1 only (fast, default)
vyber-scan scan ./my-project

# Layer 1 + Semgrep (Layer 2)
vyber-scan scan ./my-project --full

# Full audit: all layers, write reports to .security/reports/
vyber-scan scan ./my-project --audit

# Add Claude-powered triage to filter false positives
vyber-scan scan ./my-project --ai-triage   # requires ANTHROPIC_API_KEY

# JSON output for CI integration
vyber-scan scan ./my-project --json -o report.md

# Fail CI on high or above
vyber-scan scan ./my-project --fail-on high
```

### Example output

```
[CRITICAL] api/admin/users.ts:14    Admin route marked TODO/FIXME - likely unauthenticated
[CRITICAL] .env.local:7             Stripe Secret Key
[CRITICAL] supabase/migrations/0001.sql:23   Supabase RLS policy with USING (true) - allows all
[HIGH]     server/cors.py:8         FastAPI/Starlette CORS: allow_origins=['*'] exposes API to any domain
[WARNING]  app/(tabs)/profile.tsx:42   Reference to google_tokens table - ensure OAuth tokens are encrypted at rest

Scanned 247 files. 5 findings (3 critical, 1 high, 1 warning).
```

### CI integration

Add to `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  vyber-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install vybersecurity
      - run: vyber-scan scan . --fail-on critical
```

## Configuration

Drop a `.vybersecurity.yml` at your project root to control the scan:

```yaml
enabled_modules:
  - secrets
  - auth
  - config
  - antigravity
severity_threshold: warning
output_dir: .security/reports
exclude_paths:
  - tests/fixtures
  - vendor
```

## How VyberSecurity is different

| Tool          | Pattern speed | Stack-aware  | LLM triage | OWASP LLM rules | Vibe-code focus |
|---------------|---------------|--------------|------------|-----------------|-----------------|
| Bandit        | fast          | Python only  | no         | no              | no              |
| Semgrep       | medium        | broad        | no         | partial         | no              |
| gitleaks      | fast          | secrets only | no         | no              | no              |
| Snyk          | medium        | broad        | partial    | partial         | no              |
| **VyberSecurity** | **fast**  | **Next.js, Expo, Supabase, Stripe, FastAPI** | **yes (Claude)** | **yes** | **yes**         |

VyberSecurity's moat is the combination of stack-specific rules (the patterns AI tools actually trigger when generating Next.js + Supabase + Stripe code) and the LLM triage layer that filters generic-pattern false positives.

## Architecture

```
src/vybersecurity/
├── cli.py             # Click-based CLI entry point
├── scanner.py         # Layer 1 orchestrator
├── patterns/
│   ├── secrets.py     # Hardcoded credentials
│   ├── auth.py        # JWT, CORS, RLS, admin routes
│   ├── config.py      # General config security
│   └── antigravity.py # Stack-specific (Expo, Supabase, FastAPI)
├── triage.py          # Layer 3: Claude-powered triage
├── stride.py          # Layer 4: STRIDE threat model
├── dast.py            # Layer 4: runtime web testing
├── reporter.py        # Console, Markdown, JSON output
├── models.py          # Pydantic finding + result schemas
└── config.py          # .vybersecurity.yml loader
```

Tests live in `tests/`. Run with `pytest`.

## Source attribution

VyberSecurity adapts patterns from several MIT-licensed scanners. See [ATTRIBUTION.md](ATTRIBUTION.md) for the full provenance, and [NOTICE](NOTICE) for Apache 2.0 attribution. Semgrep is invoked as a subprocess only (never imported), so the LGPL boundary is respected.

## Status

Pre-release. Version 0.1.0. Stable enough to run on real projects, evolving fast on rule coverage and the AI triage layer. Issues and PRs welcome.

## Roadmap

- [ ] Publish to PyPI
- [ ] SARIF output mode (for GitHub Security tab integration)
- [ ] Auto-fix mode: scanner finds an issue, Claude proposes a fix, optionally applies it
- [ ] Per-framework rule packs (Drizzle ORM, Prisma, tRPC, Hono, more)
- [ ] OWASP LLM Top 10 deep coverage: prompt injection sinks, agent permission analysis, tool definition leaks
- [ ] VS Code extension
- [ ] Pre-commit hook installer

## Contributing

Found a vibe-coded vulnerability pattern that VyberSecurity misses? Open an issue with a minimal repro, or send a PR adding the rule to the matching `patterns/*.py` module. Add a test in `tests/` showing the rule fires on the bad pattern and skips clean code.

## License

MIT. See [LICENSE](LICENSE) and [ATTRIBUTION.md](ATTRIBUTION.md) for full details.

## Related work

- [OWASP Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic AI 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
