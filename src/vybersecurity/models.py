"""Core data models."""

from __future__ import annotations

from pydantic import BaseModel


class Finding(BaseModel):
    rule_id: str
    severity: str  # "critical" | "high" | "warning" | "info"
    filename: str
    line_number: int
    line_content: str
    description: str

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.filename}:{self.line_number} - {self.description}"


class ScanResult(BaseModel):
    target: str
    findings: list[Finding] = []
    files_scanned: int = 0

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]
