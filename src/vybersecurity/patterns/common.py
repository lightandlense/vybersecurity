"""Shared utilities for pattern scanning."""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Generator

EXCLUDED_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "coverage", ".cache",
    "__pycache__", ".pytest_cache", ".ruff_cache",
}

# Lock files contain package hashes that trigger false positives
EXCLUDED_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "Gemfile.lock",
    "composer.lock", "cargo.lock",
}


def is_excluded_path(path_str: str) -> bool:
    normalized = path_str.replace("\\", "/")
    parts = normalized.split("/")
    filename = parts[-1] if parts else ""
    return any(part in EXCLUDED_DIRS for part in parts) or filename in EXCLUDED_FILENAMES


def walk_files(root: str) -> Generator[Path, None, None]:
    """Yield all files under root, pruning excluded directories at traversal time."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for fname in filenames:
            if fname not in EXCLUDED_FILENAMES:
                yield Path(dirpath) / fname


def should_ignore(line: str, rule_id: str) -> bool:
    """Check for # vyber-ignore or # vyber-ignore:rule_id inline suppression."""
    if "vyber-ignore" not in line:
        return False
    match = re.search(r"vyber-ignore(?::\s*([a-zA-Z0-9_,\s]*))?", line)
    if match:
        specific = match.group(1)
        if specific:
            specific = specific.replace("*/", "").replace("-->", "").strip()
            return rule_id in [r.strip() for r in specific.split(",")]
        return True
    return False


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def is_false_positive_line(line: str) -> bool:
    """Skip lines that are clearly examples or placeholders."""
    lower = line.lower()
    return any(w in lower for w in [
        "example", "placeholder", "your_", "your-", "<your", "xxx",
        "replace_me", "changeme", "fake", "dummy",
    ])
