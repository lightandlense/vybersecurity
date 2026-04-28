"""Tests for Phase 6a STRIDE threat modeling."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vybersecurity.stride import STRIDE_CATEGORIES, StrideReport, generate_stride_report


def _mock_response(content: str) -> MagicMock:
    resp = MagicMock()
    resp.content = [MagicMock(text=content)]
    return resp


SAMPLE_STRIDE_OUTPUT = """
## Spoofing
- Attacker impersonates a calendar owner to view private events.

## Tampering
- Event data modified in transit without detection.

## Repudiation
- User denies creating a booking; no audit log exists.

## Information Disclosure
- OAuth tokens leaked via URL parameters in redirect.

## Denial of Service
- Flooding the booking endpoint with requests exhausts slots.

## Elevation of Privilege
- Guest user accesses admin-only calendar management routes.
"""


class TestStrideApiKey:
    def test_raises_without_api_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
            generate_stride_report("appointment booking", "Callitin")

    def test_accepts_explicit_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with patch("vybersecurity.stride.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(SAMPLE_STRIDE_OUTPUT)
            report = generate_stride_report("appointment booking", "Callitin", api_key="sk-fake")
        assert isinstance(report, StrideReport)

    def test_reads_env_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
        with patch("vybersecurity.stride.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(SAMPLE_STRIDE_OUTPUT)
            report = generate_stride_report("appointment booking", "Callitin")
        assert isinstance(report, StrideReport)


class TestStrideOutput:
    @pytest.fixture
    def report(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.stride.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(SAMPLE_STRIDE_OUTPUT)
            return generate_stride_report("appointment booking", "Callitin")

    def test_returns_stride_report(self, report):
        assert isinstance(report, StrideReport)

    def test_report_has_feature_name(self, report):
        assert report.feature == "appointment booking"

    def test_report_has_project_name(self, report):
        assert report.project == "Callitin"

    def test_report_has_markdown_content(self, report):
        assert len(report.markdown) > 50
        assert "Spoofing" in report.markdown

    def test_report_to_markdown_includes_header(self, report):
        md = report.to_markdown()
        assert "STRIDE" in md
        assert "appointment booking" in md
        assert "Callitin" in md


class TestStridePromptCaching:
    def _call_kwargs(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.stride.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(SAMPLE_STRIDE_OUTPUT)
            generate_stride_report("appointment booking", "Callitin")
            return mock_ant.Anthropic.return_value.messages.create.call_args[1]

    def test_system_prompt_cached(self, monkeypatch):
        kwargs = self._call_kwargs(monkeypatch)
        system = kwargs["system"]
        assert isinstance(system, list)
        assert system[0].get("cache_control") == {"type": "ephemeral"}

    def test_uses_sonnet_model(self, monkeypatch):
        kwargs = self._call_kwargs(monkeypatch)
        assert kwargs["model"] == "claude-sonnet-4-6"

    def test_feature_and_project_in_prompt(self, monkeypatch):
        kwargs = self._call_kwargs(monkeypatch)
        user_content = kwargs["messages"][0]["content"]
        assert "appointment booking" in user_content
        assert "Callitin" in user_content


class TestStrideCategories:
    def test_all_six_categories_defined(self):
        expected = {
            "Spoofing", "Tampering", "Repudiation",
            "Information Disclosure", "Denial of Service", "Elevation of Privilege",
        }
        assert set(STRIDE_CATEGORIES.keys()) == expected
