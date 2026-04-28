"""Phase 4 LLM triage layer tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vybersecurity.models import Finding, ScanResult
from vybersecurity.triage import TRIAGE_MODEL, TriageResult, triage_findings

REAL_FINDING = Finding(
    rule_id="secrets.hardcoded_api_key",
    severity="critical",
    filename="api/utils.py",
    line_number=12,
    line_content='OPENAI_API_KEY = "sk-proj-abc123xyz"',
    description="Hardcoded OpenAI API key",
)

TEST_FIXTURE_FINDING = Finding(
    rule_id="secrets.hardcoded_api_key",
    severity="high",
    filename="tests/fixtures/test_utils.py",
    line_number=5,
    line_content='api_key = "sk-test-fakekeyfortesting"',
    description="Hardcoded API key in test fixture",
)


def _mock_response(verdicts: list[str]) -> MagicMock:
    resp = MagicMock()
    resp.content = [MagicMock(text="\n".join(verdicts))]
    return resp


@pytest.fixture
def result_two_findings():
    r = ScanResult(target="/fake/project", files_scanned=10)
    r.findings = [REAL_FINDING, TEST_FIXTURE_FINDING]
    return r


@pytest.fixture
def result_empty():
    return ScanResult(target="/fake/project", files_scanned=5)


# --- API key validation ---

class TestApiKeyValidation:
    def test_raises_when_no_env_key(self, result_two_findings, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
            triage_findings(result_two_findings)

    def test_explicit_key_bypasses_env_check(self, result_empty):
        # Empty findings means no API call; just tests the key-check path
        result = triage_findings(result_empty, api_key="sk-fake")
        assert isinstance(result, TriageResult)

    def test_env_key_used_when_no_explicit_key(self, result_empty, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
        result = triage_findings(result_empty)
        assert isinstance(result, TriageResult)


# --- Empty findings shortcut ---

class TestEmptyFindings:
    def test_returns_empty_triage_without_api_call(self, result_empty, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            result = triage_findings(result_empty)
            mock_ant.Anthropic.assert_not_called()
        assert result.confirmed == []
        assert result.dismissed == []
        assert result.uncertain == []


# --- Verdict parsing ---

class TestVerdictParsing:
    def test_all_confirm(self, result_two_findings, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["CONFIRM", "CONFIRM"])
            result = triage_findings(result_two_findings)
        assert len(result.confirmed) == 2
        assert result.dismissed == []
        assert result.uncertain == []

    def test_all_dismiss(self, result_two_findings, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["DISMISS", "DISMISS"])
            result = triage_findings(result_two_findings)
        assert result.confirmed == []
        assert len(result.dismissed) == 2

    def test_mixed_verdicts(self, result_two_findings, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["CONFIRM", "DISMISS"])
            result = triage_findings(result_two_findings)
        assert result.confirmed == [REAL_FINDING]
        assert result.dismissed == [TEST_FIXTURE_FINDING]
        assert result.uncertain == []

    def test_uncertain_verdict(self, result_two_findings, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["UNCERTAIN", "UNCERTAIN"])
            result = triage_findings(result_two_findings)
        assert len(result.uncertain) == 2

    def test_short_response_falls_back_to_uncertain(self, result_two_findings, monkeypatch):
        """Claude returns fewer lines than findings: extras become UNCERTAIN."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["CONFIRM"])
            result = triage_findings(result_two_findings)
        assert len(result.confirmed) == 1
        assert len(result.uncertain) == 1

    def test_unknown_verdict_treated_as_uncertain(self, result_two_findings, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["CONFIRM", "MAYBE"])
            result = triage_findings(result_two_findings)
        assert len(result.confirmed) == 1
        assert len(result.uncertain) == 1


# --- Prompt caching and model correctness ---

class TestPromptCaching:
    def _call_kwargs(self, result, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        with patch("vybersecurity.triage.anthropic") as mock_ant:
            mock_ant.Anthropic.return_value.messages.create.return_value = _mock_response(["CONFIRM", "DISMISS"])
            triage_findings(result)
            return mock_ant.Anthropic.return_value.messages.create.call_args[1]

    def test_system_prompt_has_ephemeral_cache_control(self, result_two_findings, monkeypatch):
        kwargs = self._call_kwargs(result_two_findings, monkeypatch)
        system = kwargs["system"]
        assert isinstance(system, list), "system must be a list for caching"
        assert system[0].get("cache_control") == {"type": "ephemeral"}

    def test_system_prompt_is_text_type(self, result_two_findings, monkeypatch):
        kwargs = self._call_kwargs(result_two_findings, monkeypatch)
        system = kwargs["system"]
        assert system[0].get("type") == "text"
        assert len(system[0].get("text", "")) > 50

    def test_uses_correct_model(self, result_two_findings, monkeypatch):
        kwargs = self._call_kwargs(result_two_findings, monkeypatch)
        assert kwargs["model"] == TRIAGE_MODEL

    def test_all_findings_included_in_prompt(self, result_two_findings, monkeypatch):
        kwargs = self._call_kwargs(result_two_findings, monkeypatch)
        user_content = kwargs["messages"][0]["content"]
        assert "api/utils.py" in user_content
        assert "tests/fixtures/test_utils.py" in user_content
