"""Layer 1 scanner: orchestrates all pattern modules."""

from __future__ import annotations

import logging
from pathlib import Path

from .config import VyberConfig, load
from .models import ScanResult
from .patterns import antigravity, auth, config, secrets

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}


def _apply_threshold(result: ScanResult, threshold: str) -> ScanResult:
    cutoff = SEVERITY_ORDER.get(threshold, 3)
    result.findings = [
        f for f in result.findings
        if SEVERITY_ORDER.get(f.severity, 9) <= cutoff
    ]
    return result


def scan(target: str, vyber_config: VyberConfig | None = None) -> ScanResult:
    """Run all enabled Layer 1 pattern checks against the target directory."""
    root = Path(target).resolve()
    if not root.exists():
        raise ValueError(f"Target path does not exist: {target}")

    cfg = vyber_config or load(str(root))
    result = ScanResult(target=str(root))

    result.files_scanned = sum(1 for p in root.rglob("*") if p.is_file())
    log.info("Scanning %s (%d files)", root, result.files_scanned)

    modules = cfg.enabled_modules
    if "secrets" in modules:
        result.findings.extend(secrets.scan_directory(str(root)))
    if "auth" in modules:
        result.findings.extend(auth.scan_directory(str(root)))
    if "config" in modules:
        result.findings.extend(config.scan_directory(str(root)))
    if "antigravity" in modules:
        result.findings.extend(antigravity.scan_directory(str(root)))

    # Deduplicate by (rule_id, filename, line_number)
    seen: set[tuple[str, str, int]] = set()
    deduped = []
    for f in result.findings:
        key = (f.rule_id, f.filename, f.line_number)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    result.findings = deduped

    # Apply severity threshold from config
    result = _apply_threshold(result, cfg.severity_threshold)

    log.info("Scan complete: %d findings", len(result.findings))
    return result
