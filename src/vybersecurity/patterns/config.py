"""Configuration hygiene checks: .gitignore coverage, missing gitignore, .env exposure."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from .common import is_excluded_path

# .env variants that should always be in .gitignore
SENSITIVE_ENV_PATTERNS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.vercel",
    ".env.*.local",
    "*.local.yml",
    "*.local.yaml",
]

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php"}


def check_gitignore_coverage(directory: str) -> list[Finding]:
    """Flag .env.* files present in the directory that aren't covered by .gitignore."""
    findings: list[Finding] = []
    root = Path(directory)
    gitignore_path = root / ".gitignore"

    gitignore_lines: list[str] = []
    if gitignore_path.exists():
        gitignore_lines = gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    def is_ignored(filename: str) -> bool:
        return any(
            pat.strip().rstrip("/") in filename or filename == pat.strip()
            for pat in gitignore_lines
            if pat.strip() and not pat.strip().startswith("#")
        )

    for p in root.rglob("*"):
        if not p.is_file() or is_excluded_path(str(p)):
            continue
        name = p.name.lower()
        if name.startswith(".env") and name != ".env.example" and name != ".env.sample":
            if not is_ignored(p.name) and not is_ignored(name):
                findings.append(Finding(
                    rule_id="env_not_gitignored",
                    severity="critical",
                    filename=str(p),
                    line_number=1,
                    line_content=p.name,
                    description=f"Sensitive file '{p.name}' not covered by .gitignore - risk of committing secrets",
                ))

    return findings


def check_missing_gitignore(directory: str) -> list[Finding]:
    """Flag directories containing source files but no .gitignore."""
    findings: list[Finding] = []
    root = Path(directory)

    # Check root first
    has_source = any(p.suffix in SOURCE_EXTENSIONS for p in root.iterdir() if p.is_file())
    has_gitignore = (root / ".gitignore").exists()

    if has_source and not has_gitignore:
        findings.append(Finding(
            rule_id="missing_gitignore",
            severity="high",
            filename=str(root),
            line_number=1,
            line_content="",
            description="Directory contains source files but has no .gitignore - secrets risk",
        ))

    # Check immediate subdirectories that look like backend/service roots
    for subdir in root.iterdir():
        if not subdir.is_dir() or is_excluded_path(str(subdir)):
            continue
        name = subdir.name.lower()
        if any(kw in name for kw in ["backend", "server", "api", "service", "worker"]):
            sub_has_source = any(p.suffix in SOURCE_EXTENSIONS for p in subdir.rglob("*") if p.is_file())
            sub_has_gitignore = (subdir / ".gitignore").exists() or has_gitignore
            if sub_has_source and not sub_has_gitignore:
                findings.append(Finding(
                    rule_id="missing_gitignore",
                    severity="high",
                    filename=str(subdir),
                    line_number=1,
                    line_content="",
                    description=f"Backend directory '{subdir.name}' has source files but no .gitignore",
                ))

    return findings


def check_api_key_reuse(directory: str) -> list[Finding]:
    """Detect the same high-value API key value appearing in multiple .env files."""
    import re
    findings: list[Finding] = []
    root = Path(directory)

    # Map: key_value -> list of (filepath, line_number)
    key_occurrences: dict[str, list[tuple[str, int]]] = {}

    key_pattern = re.compile(
        r"(?:sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9_-]{20,}|AIza[0-9A-Za-z\-_]{20,}|ghp_[a-zA-Z0-9]{20,})"
    )

    for p in root.rglob("*"):
        if not p.is_file() or is_excluded_path(str(p)):
            continue
        name = p.name.lower()
        if not name.startswith(".env"):
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for match in key_pattern.finditer(line):
                val = match.group(0)
                key_occurrences.setdefault(val, []).append((str(p), i))

    for val, occurrences in key_occurrences.items():
        if len(occurrences) >= 2:
            locations = ", ".join(f"{fp}:{ln}" for fp, ln in occurrences[:5])
            preview = val[:12] + "..."
            findings.append(Finding(
                rule_id="api_key_reuse",
                severity="high",
                filename=occurrences[0][0],
                line_number=occurrences[0][1],
                line_content=preview,
                description=f"API key '{preview}' reused across {len(occurrences)} files: {locations}",
            ))

    return findings


def scan_directory(path: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_gitignore_coverage(path))
    findings.extend(check_missing_gitignore(path))
    findings.extend(check_api_key_reuse(path))
    return findings
