# Devon, Start Here

This is your handoff. Read in this order:

1. CLAUDE.md (your identity, folder structure, rules)
2. CONTEXT.md (what we're building, success criteria, all decisions locked)
3. REFERENCES.md (source repos, license boundaries, security baseline canary tests)

Then start Phase 1.

# Phase 1 (Day 1): Skeleton & License Hygiene

Done when: `pip install -e .` works, `vyber-scan --help` prints usage, LICENSE + ATTRIBUTION + NOTICE files exist, repo structure matches CLAUDE.md.

## Concrete tasks

1. `cd E:/Antigravity/Projects/vybersecurity/`
2. `git init` if not already
3. Create Python project skeleton:
   - `pyproject.toml` (Python 3.11+, hatchling backend, project name "vybersecurity", entry point `vyber-scan = vybersecurity.cli:main`)
   - `src/vybersecurity/__init__.py`
   - `src/vybersecurity/cli.py` with a Click app that prints `--help`
   - `tests/test_cli.py` with one passing test for `--help`
4. Dev dependencies: pytest, ruff, click, pydantic
5. Add `LICENSE` (MIT, Russell as copyright holder)
6. Add `ATTRIBUTION.md` with the table from REFERENCES.md (only sources we'll actually use: Vibe-Guard MIT, VibePenTester Apache 2.0, VibeSecurity MIT, IRIS MIT)
7. Add `NOTICE` (Apache 2.0 NOTICE file for VibePenTester usage when we get there)
8. Add `.gitignore` (Python defaults + `.security/reports/` + `.env` + `*.local.yml`)
9. Add minimal `README.md` with one-line description, install instruction (`pip install vybersecurity` — note: "coming soon to PyPI"), and link to GitHub
10. Verify: `pip install -e .` works in a fresh venv
11. Verify: `vyber-scan --help` prints
12. Verify: `pytest` passes
13. Verify: `ruff check .` is clean
14. First commit: `feat: initial project skeleton with MIT license and CLI scaffold`

## Phase 1 deliverable

Push to GitHub as a public repo: `https://github.com/<russell>/vybersecurity`. Use `gh repo create` with `--public --description "Security scanner for vibe-coded projects"`.

When Phase 1 is done, ping Russell on Telegram (chat_id 1606798823) with:
- The repo URL
- Output of `vyber-scan --help`
- Brief: "Phase 1 done. Starting Phase 2 (pattern aggregation)."

# Decisions Locked (don't re-litigate)

- Repo: PUBLIC at launch
- License (project itself): MIT
- Distribution: PyPI
- LLM triage: OPT-IN (`--ai-triage` flag)
- Name: VyberSecurity, CLI is `vyber-scan`

# Open Calls You Can Make Yourself

These are small, ship reasonable defaults:
- Pre-commit framework: pre-commit + ruff + your security-reviewer agent
- Test framework: pytest
- Type checking: skip mypy for now, add in Phase 4 if useful
- Logging: stdlib `logging`, no extra deps
- Config file format: YAML (Pydantic supports it cleanly)

# Ask Russell First Before

- Adding any dependency not on the list (Click, Pydantic, Anthropic SDK, pytest, ruff, semgrep, playwright)
- Changing the architecture from CONTEXT.md
- Skipping any of the 10 canary tests in REFERENCES.md
- Anything that touches AGPL boundaries (just don't)

# After Phase 1

Move on to Phase 2 (Pattern Layer). Re-read REFERENCES.md for what to take from each source repo.
