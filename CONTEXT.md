# Current Project

Building VyberSecurity, a Python CLI security scanner for vibe-coded projects. It runs as a 4-layer pipeline: fast regex pattern scan, LLM triage to filter false positives, optional STRIDE threat modeling, optional DAST. Targets Russell's own Antigravity projects first, with potential to release as open source.

# What good looks like

A `pip install -e .` followed by `vyber-scan E:/Antigravity/Projects/Callitin --full` produces a clean, actionable Markdown report at `.security/reports/` in under 2 minutes. The report flags all 10 known issues from Russell's April 2026 security audit (see REFERENCES.md). False positive rate under 5% on a known-clean project. Pre-commit hook on Callitin runs in under 5 seconds and blocks pushes containing hardcoded secrets.

The CLI is single-binary feeling. Output is human-readable. Attribution is clean. Nothing AGPL-tainted.

# What to avoid

- Copying code from SecureVibes (AGPL-3.0). Read for inspiration, write STRIDE prompt clean-room
- Copying anything from VibeDoctor (no public license, all rights reserved)
- Modifying Semgrep source or importing it as a library (LGPL contamination). Subprocess only
- Forgetting NOTICE file when copying from VibePenTester (Apache 2.0 requires it)
- Building a feature that already exists in Vibe-Guard. Use their patterns, do not reinvent
- Premature abstraction. Start concrete, refactor when patterns repeat 3+ times
- Heavy dependencies. Stay close to stdlib + Click + Pydantic + Anthropic SDK + Semgrep subprocess
- Silent failures. Every scanner must emit either findings or "scan complete, no issues" log lines
- Burning Anthropic tokens. LLM triage must use prompt caching per Russell's claude-api skill rules

# Phases

Lightweight, not GSD-formal. Each phase is "what done looks like" for a chunk of work.

**Phase 1: Skeleton & License Hygiene (Day 1)**
Done when: pyproject.toml works, `vyber-scan --help` prints usage, LICENSE/ATTRIBUTION/NOTICE files exist, repo structure matches CLAUDE.md.

**Phase 2: Pattern Layer (Day 2)**
Done when: Layer 1 scanner runs and flags all 10 known issues from REFERENCES.md security baseline. Includes Vibe-Guard ports, VibeSecurity ports, and Antigravity-specific patterns (Telegram bot tokens, webhook HMAC, Expo conventions).

**Phase 3: Runner CLI (Day 3)**
Done when: `vyber-scan <dir> --quick|--full|--audit` produces JSON + Markdown reports. Config via `.vybersecurity.yml`. Ignore comments work (`# vyber-ignore`).

**Phase 4: LLM Triage (Day 4)**
Done when: Claude Sonnet 4.6 triage layer cuts false positives by 50%+ on a representative test repo. Cross-references project_security_audit memory. Prompt caching active.

**Phase 5: Hooks & CI (Day 5 morning)**
Done when: Husky pre-commit hook installed on Callitin runs Layer 1 in under 5s. GitHub Actions workflow runs Layers 1+2 on PR. Both block on critical findings.

**Phase 6 (optional): STRIDE & DAST (Day 5 afternoon)**
Done when: STRIDE threat model template (clean-room) generates usable output for a Callitin feature in under 5 minutes. Playwright-based DAST catches a planted XSS in a test build.

# Decisions (locked 2026-04-27)

1. Repo visibility: PUBLIC at launch
2. License: MIT (project itself)
3. Distribution: PyPI (`pip install vybersecurity`)
4. LLM triage: OPT-IN. Default scan runs only Layer 1 (fast pattern). Add `--ai-triage` to invoke Layer 2. Anthropic API key required only when user opts in.
5. Name: VyberSecurity (CLI: `vyber-scan`)

# Status

Spec drafted by Jeeves on 2026-04-27. Restructured into ICM format. All open questions answered. Cleared for Devon to start Phase 1.
