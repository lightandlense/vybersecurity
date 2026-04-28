# VyberSecurity

A unified vibe-code security scanner that combines battle-tested OSS pattern libraries with Antigravity's stack-aware LLM triage.

## Why This Exists

91.5% of vibe-coded apps in Q1 2026 had at least one AI-hallucination vulnerability. AI code has 2.74x the flaw rate of human code. Existing tools either:
- Pattern-match fast but lack stack context (Vibe-Guard, Semgrep)
- Reason deeply but require LLM invocation per file (Russell's current security-reviewer agent)
- Cost money and lock you into their cloud (PreBreach, VibeDoctor SaaS)

VyberSecurity bridges these. Fast pattern layer for every commit, LLM triage layer for context-aware filtering, all open source, all runnable on Russell's machine.

## Architecture

Four-layer pipeline, each layer adds time but reduces noise.

```
project files
    |
    v
Layer 1: Fast pattern scan      (seconds)
  - Adapted Vibe-Guard regex (9 platform tokens, JWT alg:none, IaC, RCE)
  - Antigravity-specific patterns (Telegram bot tokens, webhook HMAC, Expo conventions)
  - Semgrep subprocess with curated rule pack
    |
    v
Layer 2: LLM triage              (1-2 min)
  - Claude Sonnet 4.6 classifies findings: real / false positive / context-dependent
  - Cross-references project_security_audit memory to suppress known-and-accepted
  - Filters output for actionable findings only
    |
    v
Layer 3: STRIDE threat model     (on demand)
  - Custom prompt template (clean-room, NOT derived from AGPL SecureVibes)
  - Triggers on new feature additions or pre-deploy
    |
    v
Layer 4: DAST                    (quarterly)
  - Live web testing for runtime-only vulns
  - Auth flow, race condition, runtime auth bypass checks
```

## Source Attribution Plan

| Source | License | What we take | How we take it |
|---|---|---|---|
| Vibe-Guard | MIT | Regex patterns, AI-pattern checks, .cursorrules generator | Copy patterns into our scanners/, attribute in ATTRIBUTION.md |
| VibePenTester | Apache 2.0 | Multi-agent orchestration, report templates | Copy + NOTICE file required |
| VibeSecurity | MIT | Web vulnerability checks | Copy + attribute |
| IRIS | MIT | Whole-repo cross-file data flow approach | Adapt methodology |
| Semgrep | LGPL-2.1 | The engine itself | Subprocess only, never modify or import as library |
| SecureVibes | AGPL-3.0 | DO NOT COPY | Read for inspiration, write STRIDE template clean-room |
| VibeDoctor | None | DO NOT COPY | Skip entirely |

## Tech Stack

- Python 3.11+ (Vibe-Guard is Python, fits naturally)
- Click for CLI
- Pydantic for config + result schemas
- Anthropic SDK for LLM triage layer
- Semgrep CLI as subprocess
- pytest + ruff
- Husky for git hooks
- GitHub Actions for CI

## Project Structure

```
antigravity-shield/
├── README.md
├── LICENSE                           # MIT
├── ATTRIBUTION.md                    # All source attributions
├── NOTICE                            # Apache 2.0 NOTICE for VibePenTester
├── pyproject.toml
├── .antigravity-shield.yml.example   # Config template
├── src/
│   └── antigravity_shield/
│       ├── __init__.py
│       ├── cli.py                    # Entry point: antigravity-scan
│       ├── scanners/
│       │   ├── secrets.py            # Token regex (from Vibe-Guard)
│       │   ├── web.py                # Web vulns (from VibeSecurity)
│       │   ├── iac.py                # IaC checks (from Vibe-Guard)
│       │   ├── auth.py               # JWT, cookies, RLS (from Vibe-Guard)
│       │   ├── rce.py                # eval/os.system/subprocess (from Vibe-Guard)
│       │   ├── antigravity.py        # Custom: Telegram, HMAC, Expo
│       │   └── semgrep_runner.py     # Subprocess wrapper
│       ├── triage/
│       │   ├── llm_triage.py         # Claude Sonnet 4.6 classifier
│       │   └── memory_filter.py      # Cross-ref project_security_audit
│       ├── reports/
│       │   ├── markdown.py           # Markdown report (from VibePenTester)
│       │   ├── json_report.py        # JSON schema
│       │   └── templates/
│       ├── stride/
│       │   └── threat_model.py       # Clean-room STRIDE
│       └── dast/
│           └── runner.py             # Live web testing
├── rules/
│   └── semgrep/                      # Curated Semgrep rule pack
├── tests/
│   ├── fixtures/
│   │   └── vulnerable_apps/          # Test apps with known vulns
│   ├── test_scanners.py
│   ├── test_triage.py
│   └── test_e2e.py
├── hooks/
│   ├── pre-commit                    # Husky pre-commit script
│   └── github-actions.yml            # CI workflow template
└── docs/
    ├── installation.md
    ├── configuration.md
    └── rules.md
```

## Phases

### Phase 1: Foundation (Day 1)
**Goal:** Repo initialized, attribution complete, project skeleton in place.

Tasks:
1. Initialize Python project with pyproject.toml
2. Set up ruff, pytest, pre-commit basics
3. Write LICENSE (MIT), ATTRIBUTION.md, NOTICE
4. Create directory skeleton matching structure above
5. Write README with overview + quickstart
6. Set up GitHub repo (private to start)

Success criteria: `pip install -e .` works, `antigravity-scan --help` prints usage.

### Phase 2: Pattern Aggregation (Day 2)
**Goal:** Layer 1 (fast pattern scan) runs and detects all 10 known issues from Russell's project_security_audit.

Tasks:
1. Port Vibe-Guard regex patterns into scanners/secrets.py
2. Port Vibe-Guard auth checks (JWT alg:none, cookie flags) into scanners/auth.py
3. Port Vibe-Guard IaC checks into scanners/iac.py
4. Port Vibe-Guard RCE patterns into scanners/rce.py
5. Port VibeSecurity web checks into scanners/web.py
6. Write Antigravity-specific patterns in scanners/antigravity.py:
   - Telegram bot token format (digits:alphanumeric)
   - Webhook HMAC pattern detection
   - Expo EXPO_PUBLIC_ misuse
   - Antigravity .env structure
7. Write Semgrep subprocess wrapper
8. Write test fixtures (vulnerable mini-apps) for each rule

Success criteria: Running on Callitin catches the unencrypted google_tokens issue. Running on Spoon Admin catches the trivially-forgeable cookie. All 10 known issues from project_security_audit get flagged.

### Phase 3: Runner CLI (Day 3)
**Goal:** Single CLI command runs Layer 1 end-to-end with structured output.

Tasks:
1. Click-based CLI: `antigravity-scan <project-dir>` with subcommands
2. --quick flag for Layer 1 only
3. --full flag for Layers 1+2
4. --audit flag for all layers
5. JSON output schema (Pydantic models)
6. Markdown report generator (port VibePenTester templates)
7. Exit codes: 0 clean, 1 issues found, 2 critical
8. Config file support (.antigravity-shield.yml)
9. Ignore patterns (vibe-ignore comment style from Vibe-Guard)

Success criteria: `antigravity-scan E:/Antigravity/Projects/Callitin --full` produces markdown report at .security/reports/.

### Phase 4: LLM Triage Layer (Day 4)
**Goal:** Layer 2 cuts false positives by 50%+ vs raw scanner output.

Tasks:
1. Anthropic SDK integration with prompt caching
2. Triage prompt template that classifies each finding
3. Cross-reference loader for project_security_audit memory
4. Filtering logic (real / false positive / known-and-accepted / needs-review)
5. Cost guardrails (cap tokens per scan, per project)
6. Token usage logging

Success criteria: On a known-clean project, false positive rate <5%. On Callitin, triage agrees with Russell's manual classification on 8/10 issues.

### Phase 5: Hooks + CI (Day 5 morning)
**Goal:** Scanner runs automatically on every commit and PR.

Tasks:
1. Husky pre-commit hook script (Layer 1 only, <5s)
2. GitHub Actions workflow (Layers 1+2 on PR)
3. Install on Callitin as proof of concept
4. Documentation: installation.md, configuration.md
5. Annotation comments on PRs with findings

Success criteria: Push a fake hardcoded API key to a Callitin test branch. Pre-commit blocks it. CI flags it on PR.

### Phase 6: STRIDE + DAST (Day 5 afternoon, OPTIONAL)
**Goal:** Layers 3 and 4 available for pre-deploy and quarterly audits.

Tasks:
1. STRIDE threat model prompt (clean-room, not derived from SecureVibes)
2. Threat model output as Markdown table
3. DAST runner using Playwright (already in Russell's stack)
4. Common test cases: XSS, SQLi, auth bypass, IDOR
5. Quarterly audit mode that runs all layers + saves report

Success criteria: STRIDE produces a usable threat model for Callitin in <5 min. DAST catches a fake XSS planted in a test build.

## Total Estimated Effort
4.5 to 5.5 days for Devon.

## Success Metrics (post-launch)
- Catches all 10 known issues from project_security_audit on first run
- Layer 1 runs in <30 seconds on Callitin-sized repo
- Layer 2 LLM triage cuts false positives by >50%
- Pre-commit hook completes in <5 seconds
- Markdown reports are readable without context
- Zero false positives on the security-audit skill checklist itself
- Open source release with clean attribution

## Future / Out of Scope (v2+)
- MCP server wrapper (so Claude Code can call it as a tool)
- Web dashboard for findings across all projects
- Auto-fix suggestions via LLM
- Vibe-coding client SaaS offering
- Browser extension for live scanning Lovable/Bolt outputs

## Open Questions for Russell
1. Public repo at launch or private until polished?
2. License: MIT (max adoption) or AGPL (force open source from forks)?
3. Distribute on PyPI or just install from source?
4. Should Layer 2 LLM triage default ON or be opt-in (cost concern)?
5. Naming: AntigravityShield, antigravity-scan, vibe-shield, something else?

## Build Owner
Devon (or Devon 2 for parallel work)

## Current Status
Spec drafted by Jeeves on 2026-04-27. Awaiting Russell's go to kick off Phase 1.
