"""Load and validate .vybersecurity.yml project config."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class VyberConfig(BaseModel):
    exclude: list[str] = Field(default_factory=list)
    severity_threshold: str = "info"  # minimum severity to report
    output_dir: str = ".security/reports"
    enabled_modules: list[str] = Field(
        default_factory=lambda: ["secrets", "auth", "config", "antigravity"]
    )
    # Extra paths to always ignore (on top of built-in excluded dirs)
    ignore_paths: list[str] = Field(default_factory=list)


_DEFAULTS = VyberConfig()


def load(target: str) -> VyberConfig:
    """Load .vybersecurity.yml from target dir, return defaults if absent."""
    config_path = Path(target) / ".vybersecurity.yml"
    if not config_path.exists():
        return _DEFAULTS

    try:
        import yaml  # optional dep - only needed when config file exists
    except ImportError:
        return _DEFAULTS

    try:
        raw: Any = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return _DEFAULTS
        return VyberConfig(**raw)
    except Exception:  # noqa: BLE001
        return _DEFAULTS
