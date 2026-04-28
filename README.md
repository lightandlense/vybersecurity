# VyberSecurity

Security scanner for vibe-coded projects. Catches AI-generated code vulnerabilities before they ship.

## Install

```bash
pip install vybersecurity  # coming soon to PyPI
```

For now, install from source:

```bash
git clone https://github.com/zelkirb/vybersecurity
cd vybersecurity
pip install -e ".[dev]"
```

## Usage

```bash
vyber-scan scan ./my-project          # fast pattern scan
vyber-scan scan ./my-project --full   # pattern scan + semgrep
vyber-scan scan ./my-project --audit  # full scan + report
vyber-scan scan ./my-project --ai-triage  # enable LLM triage (requires ANTHROPIC_API_KEY)
```

## License

MIT. See [LICENSE](LICENSE) and [ATTRIBUTION.md](ATTRIBUTION.md).
