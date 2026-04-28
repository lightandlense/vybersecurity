# VyberSecurity

Security scanner for vibe-coded projects. Catches AI-generated code vulnerabilities before they ship.

91.5% of AI-assisted apps contain at least one hallucination vulnerability. VyberSecurity runs a four-layer pipeline -- fast pattern scan, Semgrep, LLM triage, and DAST -- so issues get caught before they reach production.

## What It Catches

- **Hardcoded secrets** -- API keys, tokens, passwords, private keys embedded in source
- **Auth vulnerabilities** -- JWT `alg:none` bypass, missing cookie flags (HttpOnly, Secure, SameSite), Row Level Security gaps
- **Injection risks** -- RCE via `eval`, `os.system`, unvalidated `subprocess` calls
- **Web vulnerabilities** -- XSS vectors, CSRF gaps, open redirect patterns
- **Infrastructure misconfigurations** -- IaC security issues (Terraform, Docker, k8s)
- **AI-specific patterns** -- Telegram bot token exposure, webhook HMAC bypass, `EXPO_PUBLIC_` secret leakage

## Install

```bash
pip install vybersecurity  # coming soon to PyPI
```

For now, install from source:

```bash
git clone https://github.com/lightandlense/vybersecurity
cd vybersecurity
pip install -e ".[dev]"
```

## Usage

```bash
vyber-scan scan ./my-project                   # fast pattern scan (default)
vyber-scan scan ./my-project --full            # pattern scan + Semgrep
vyber-scan scan ./my-project --audit           # full scan + write reports to .security/reports/
vyber-scan scan ./my-project --ai-triage       # add LLM triage layer (requires ANTHROPIC_API_KEY)
vyber-scan scan ./my-project --fail-on high    # exit non-zero if high/critical findings exist
```

## How It Works

Four layers, each adding depth while reducing noise:

```
Layer 1: Pattern scan    -- regex rules for secrets, auth, RCE, web vulns, IaC (seconds)
Layer 2: Semgrep         -- deeper static analysis via curated rule pack
Layer 3: LLM triage      -- Claude Sonnet classifies findings as real / false positive / needs review
Layer 4: STRIDE + DAST   -- threat modeling and live web testing for pre-deploy audits
```

Run `--quick` for pre-commit (Layer 1 only, under 5 seconds). Run `--audit --ai-triage` for a full pre-deploy sweep.

## Output

Reports are written to `.security/reports/` in both Markdown and JSON. The console view shows findings grouped by severity: `critical`, `high`, `warning`, `info`.

Exit codes: `0` clean, `1` findings at or above the `--fail-on` threshold, `2` error.

## Configuration

Create a `.vybersecurity.yml` in your project root to ignore paths, suppress known findings, or set per-project thresholds:

```yaml
ignore:
  - "tests/"
  - "node_modules/"
fail_on: high
output_dir: .security/reports
```

Suppress a specific line with an inline comment:

```python
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")  # vyber-ignore: not-a-secret
```

## CI Integration

Add to GitHub Actions:

```yaml
- name: VyberSecurity scan
  run: |
    pip install -e .
    vyber-scan scan . --full --fail-on high
```

## Attribution

Pattern library adapted from [Vibe-Guard](https://github.com/vibe-guard) (MIT), [VibeSecurity](https://github.com/vibesecurity) (MIT), and [VibePenTester](https://github.com/vibepentest) (Apache 2.0). Semgrep is invoked as a subprocess only (LGPL-2.1 boundary). See [ATTRIBUTION.md](ATTRIBUTION.md) for full credits.

## License

MIT. See [LICENSE](LICENSE) and [ATTRIBUTION.md](ATTRIBUTION.md).
