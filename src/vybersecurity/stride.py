"""Layer 3 STRIDE threat modeling via Claude Sonnet 4.6 (clean-room implementation)."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone

import anthropic

log = logging.getLogger(__name__)

STRIDE_MODEL = "claude-sonnet-4-6"

STRIDE_CATEGORIES: dict[str, str] = {
    "Spoofing": "Impersonating users, systems, or services",
    "Tampering": "Modifying data, code, or system state without authorization",
    "Repudiation": "Denying actions with no way to prove otherwise",
    "Information Disclosure": "Exposing sensitive data to unauthorized parties",
    "Denial of Service": "Making a system unavailable to legitimate users",
    "Elevation of Privilege": "Gaining unauthorized access or permissions",
}

_SYSTEM_TEXT = (
    "You are a security architect performing STRIDE threat modeling for software features.\n\n"
    "STRIDE categories:\n"
    "- Spoofing: Impersonating users or systems\n"
    "- Tampering: Modifying data or system state without authorization\n"
    "- Repudiation: Denying actions with no audit trail\n"
    "- Information Disclosure: Exposing sensitive data\n"
    "- Denial of Service: Making systems unavailable\n"
    "- Elevation of Privilege: Gaining unauthorized access\n\n"
    "For the described feature and project, identify realistic threats in each category.\n"
    "For each threat include: what the threat is, which component is affected, severity (critical/high/medium/low), "
    "and a concrete mitigation.\n\n"
    "Format output as Markdown with one section per STRIDE category (## Spoofing, etc.).\n"
    "Be specific to the described feature. Avoid generic boilerplate that applies to all software."
)


@dataclass
class StrideReport:
    feature: str
    project: str
    markdown: str
    generated_at: str

    def to_markdown(self) -> str:
        header = (
            f"# STRIDE Threat Model: {self.feature}\n\n"
            f"**Project:** {self.project}  \n"
            f"**Generated:** {self.generated_at}  \n\n"
            "---\n\n"
        )
        return header + self.markdown


def generate_stride_report(
    feature: str,
    project: str,
    api_key: str | None = None,
) -> StrideReport:
    """Generate a STRIDE threat model for a feature using Claude with prompt caching."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY is required for STRIDE threat modeling. "
            "Set it in your environment or pass api_key explicitly."
        )

    client = anthropic.Anthropic(api_key=key)

    user_content = (
        f"Project: {project}\n"
        f"Feature to threat model: {feature}\n\n"
        "Generate a STRIDE threat model for this feature."
    )

    log.info("Generating STRIDE threat model for '%s' in %s", feature, project)

    response = client.messages.create(
        model=STRIDE_MODEL,
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": _SYSTEM_TEXT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_content}],
    )

    content = response.content[0].text.strip()
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    log.info("STRIDE report generated (%d chars)", len(content))
    return StrideReport(
        feature=feature,
        project=project,
        markdown=content,
        generated_at=generated_at,
    )
