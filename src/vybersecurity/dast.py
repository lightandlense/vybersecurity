"""Layer 4 DAST: Playwright-based dynamic application security testing."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<img src=x onerror="window.__vyber_xss=true">',
    '"><script>window.__vyber_xss=true</script>',
    "';window.__vyber_xss=true;//",
]

_XSS_CHECK_JS = "() => window.__vyber_xss === true"


@dataclass
class DastFinding:
    vuln_type: str
    severity: str
    url: str
    payload: str
    description: str


@dataclass
class DastResult:
    target: str
    findings: list[DastFinding] = field(default_factory=list)


def _check_xss_via_url_params(page, base_url: str) -> list[DastFinding]:
    """Inject XSS payloads into URL query parameters and check for execution."""
    findings: list[DastFinding] = []
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    parsed = urlparse(base_url)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)

    param_names = list(existing_params.keys()) or ["q", "search", "id", "name", "input"]

    for param in param_names:
        for payload in XSS_PAYLOADS:
            test_params = dict(existing_params)
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            try:
                page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                try:
                    page.wait_for_function("window.__vyber_xss === true", timeout=2000)
                    detected = True
                except Exception:  # noqa: BLE001
                    detected = False
                if detected:
                    findings.append(DastFinding(
                        vuln_type="xss",
                        severity="high",
                        url=test_url,
                        payload=payload,
                        description=f"Reflected XSS via URL parameter '{param}' - payload executed in browser",
                    ))
                    log.info("XSS detected at %s param=%s", base_url, param)
                    break
            except Exception:  # noqa: BLE001
                continue

    return findings


def _check_xss_via_forms(page, base_url: str) -> list[DastFinding]:
    """Inject XSS payloads into form inputs and check for execution after submit."""
    findings: list[DastFinding] = []

    try:
        page.goto(base_url, wait_until="domcontentloaded", timeout=8000)
    except Exception:  # noqa: BLE001
        return findings

    forms = page.query_selector_all("form")
    for form in forms:
        inputs = form.query_selector_all("input[type='text'], input:not([type]), textarea")
        if not inputs:
            continue

        for payload in XSS_PAYLOADS:
            try:
                page.goto(base_url, wait_until="domcontentloaded", timeout=5000)
                forms_now = page.query_selector_all("form")
                if not forms_now:
                    break
                form_now = forms_now[0]
                inputs_now = form_now.query_selector_all("input[type='text'], input:not([type]), textarea")
                if not inputs_now:
                    break

                for inp in inputs_now:
                    inp.fill(payload)

                form_now.evaluate("f => f.submit()")
                page.wait_for_load_state("domcontentloaded", timeout=3000)
                detected = page.evaluate(_XSS_CHECK_JS)

                if detected:
                    findings.append(DastFinding(
                        vuln_type="xss",
                        severity="high",
                        url=page.url,
                        payload=payload,
                        description="Reflected XSS via form submission - payload executed in browser",
                    ))
                    log.info("XSS via form detected at %s", base_url)
                    return findings
            except Exception:  # noqa: BLE001
                continue

    return findings


def run_dast(url: str) -> DastResult:
    """Run DAST against a URL. Returns DastResult with any findings."""
    from playwright.sync_api import sync_playwright

    result = DastResult(target=url)
    log.info("Starting DAST scan of %s", url)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        result.findings.extend(_check_xss_via_url_params(page, url))
        if not result.findings:
            result.findings.extend(_check_xss_via_forms(page, url))

        context.close()
        browser.close()

    log.info("DAST complete: %d findings", len(result.findings))
    return result
