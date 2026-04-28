"""Tests for Phase 6b DAST: Playwright-based dynamic security testing."""

from __future__ import annotations

import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import pytest

from vybersecurity.dast import DastFinding, DastResult, run_dast

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class _FixtureHandler(SimpleHTTPRequestHandler):
    """Serves fixtures dir, suppresses logs, strips query strings from path lookup."""
    def log_message(self, *args):
        pass

    def translate_path(self, path):
        path = path.split("?", 1)[0].split("#", 1)[0].lstrip("/")
        return str(FIXTURES_DIR / path)


@pytest.fixture(scope="module")
def local_server():
    """Start a local HTTP server serving the fixtures directory."""
    server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestDastBasic:
    def test_returns_dast_result(self, local_server):
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        assert isinstance(result, DastResult)

    def test_target_url_recorded(self, local_server):
        url = f"{local_server}/xss_vulnerable.html"
        result = run_dast(url)
        assert result.target == url

    def test_findings_is_list(self, local_server):
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        assert isinstance(result.findings, list)


class TestDastXssDetection:
    def test_detects_reflected_xss(self, local_server):
        """The vulnerable fixture page reflects URL params - DAST must catch it."""
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        xss_findings = [f for f in result.findings if f.vuln_type == "xss"]
        assert len(xss_findings) >= 1, "Expected at least one XSS finding"

    def test_xss_finding_has_severity(self, local_server):
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        xss_findings = [f for f in result.findings if f.vuln_type == "xss"]
        assert all(f.severity in ("critical", "high") for f in xss_findings)

    def test_xss_finding_has_payload(self, local_server):
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        xss_findings = [f for f in result.findings if f.vuln_type == "xss"]
        assert all(f.payload for f in xss_findings)

    def test_xss_finding_has_url(self, local_server):
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        xss_findings = [f for f in result.findings if f.vuln_type == "xss"]
        assert all(f.url for f in xss_findings)


class TestDastCleanPage:
    def test_no_xss_on_safe_page(self, local_server):
        """A plain HTML page with no JS should produce no XSS findings."""
        result = run_dast(f"{local_server}/granted_auth.js")
        xss_findings = [f for f in result.findings if f.vuln_type == "xss"]
        assert len(xss_findings) == 0


class TestDastDataStructures:
    def test_dast_finding_fields(self, local_server):
        result = run_dast(f"{local_server}/xss_vulnerable.html")
        if result.findings:
            f = result.findings[0]
            assert isinstance(f, DastFinding)
            assert f.vuln_type
            assert f.severity
            assert f.url
