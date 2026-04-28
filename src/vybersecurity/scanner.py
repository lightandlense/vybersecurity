"""Layer 1 scanner: orchestrates all pattern modules."""

from __future__ import annotations

import logging
from pathlib import Path

from .models import ScanResult
from .patterns import antigravity, auth, config, secrets

log = logging.getLogger(__name__)


def scan(target: str) -> ScanResult:
    """Run all Layer 1 pattern checks against the target directory."""
    root = Path(target).resolve()
    if not root.exists():
        raise ValueError(f"Target path does not exist: {target}")

    result = ScanResult(target=str(root))

    # Count scanned files
    result.files_scanned = sum(1 for p in root.rglob("*") if p.is_file())

    log.info("Scanning %s (%d files)", root, result.files_scanned)

    # Run all pattern modules
    result.findings.extend(secrets.scan_directory(str(root)))
    result.findings.extend(auth.scan_directory(str(root)))
    result.findings.extend(config.scan_directory(str(root)))
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

    log.info("Scan complete: %d findings", len(result.findings))
    return result
