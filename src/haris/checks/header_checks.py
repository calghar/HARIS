import logging
import re
from typing import Any

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Finding, ScanContext, ScannerResult, Severity, Target
from ..net import NetworkError, ScopedResponse
from .findings import make_finding, tech_headers
from .header_policy import PolicyIssue, csp_issues, hsts_issues, parse_csp
from .requesting import fetch_page, is_html, scan_client

logger = logging.getLogger(__name__)

CSP = "Content-Security-Policy"
HSTS = "Strict-Transport-Security"
# Product followed by a version number ("nginx/1.18.0"), not a bare build id.
_VERSIONED_BANNER = re.compile(r"[A-Za-z][\w.-]*[/ ]v?\d+(?:\.\d+)*(?![\w])")

# applies: "html" headers only matter on documents, "any" on every response.
HEADER_CHECKS: list[dict[str, Any]] = [
    {
        "header": HSTS,
        "tag": "missing_hsts",
        "severity": Severity.MEDIUM,
        "applies": "https",
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "remediation": (
            "Add the header: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
    },
    {
        "header": CSP,
        "tag": "missing_security_headers",
        "severity": Severity.MEDIUM,
        "applies": "html",
        "title": "Missing Content-Security-Policy (CSP) header",
        "remediation": (
            "Implement a Content-Security-Policy header to mitigate XSS "
            "and data injection attacks."
        ),
    },
    {
        "header": "X-Content-Type-Options",
        "tag": "missing_security_headers",
        "severity": Severity.LOW,
        "applies": "any",
        "title": "Missing X-Content-Type-Options header",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "X-Frame-Options",
        "tag": "missing_security_headers",
        "severity": Severity.LOW,
        "applies": "html",
        "title": "Missing X-Frame-Options header",
        "remediation": (
            "Add: X-Frame-Options: DENY (or SAMEORIGIN). "
            "Also consider using CSP frame-ancestors directive."
        ),
    },
    {
        "header": "Referrer-Policy",
        "tag": "missing_security_headers",
        "severity": Severity.LOW,
        "applies": "html",
        "title": "Missing Referrer-Policy header",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "tag": "missing_security_headers",
        "severity": Severity.LOW,
        "applies": "html",
        "title": "Missing Permissions-Policy header",
        "remediation": (
            "Add a Permissions-Policy header to restrict browser features "
            "(camera, microphone, geolocation, etc.)."
        ),
    },
]


@register_check
class SecurityHeaderScanner(BaseScanner):
    """Missing and weak HTTP security headers on the target's front page."""

    name = "header_checks"
    version = "1.1.0"
    description = "HTTP security header analysis"

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        with scan_client(target, context) as client:
            try:
                resp = fetch_page(client, target.base_url)
            except NetworkError as exc:
                result.errors.append(f"HTTP request failed: {exc}")
                return result

        result.raw_output = str(dict(resp.headers))
        result.findings = self._check_headers(resp, target)
        result.findings.extend(self._check_header_quality(resp, target))
        result.findings.extend(self._check_server_banner(resp, target))
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    @staticmethod
    def _is_relevant(spec: dict[str, Any], resp: ScopedResponse) -> bool:
        applies = spec["applies"]
        if applies == "https":
            return resp.url.startswith("https://")
        return applies == "any" or is_html(resp)

    def _check_headers(self, resp: ScopedResponse, target: Target) -> list[Finding]:
        """Report absent headers that apply to a 2xx final response."""
        if not 200 <= resp.status_code < 300:
            logger.debug("Header presence skipped: final status %d", resp.status_code)
            return []
        csp = parse_csp(resp.headers.get(CSP, ""))
        findings: list[Finding] = []
        for spec in HEADER_CHECKS:
            header = spec["header"]
            if resp.headers.get(header) or not self._is_relevant(spec, resp):
                continue
            if header == "X-Frame-Options" and "frame-ancestors" in csp:
                continue
            report_only = header == CSP and resp.headers.get(f"{CSP}-Report-Only")
            findings.append(
                make_finding(
                    self.name,
                    "missing_header",
                    "missing_header",
                    title=spec["title"],
                    description=(
                        f"The response from {target.base_url} does not include "
                        f"the {header} header"
                        + (
                            " (a report-only policy does not enforce)."
                            if report_only
                            else "."
                        )
                    ),
                    severity=spec["severity"],
                    url=target.base_url,
                    parameter=header,
                    remediation=spec["remediation"],
                    tags=[spec["tag"]],
                    raw_data=tech_headers(resp),
                )
            )
        return findings

    def _check_header_quality(
        self, resp: ScopedResponse, target: Target
    ) -> list[Finding]:
        """Parse CSP and HSTS values that are present and flag weak settings."""
        issues: list[tuple[str, str, PolicyIssue]] = []
        if is_html(resp) and resp.headers.get(CSP):
            issues += [(CSP, "weak_csp", i) for i in csp_issues(resp.headers[CSP])]
        if resp.url.startswith("https://") and resp.headers.get(HSTS):
            issues += [(HSTS, "weak_hsts", i) for i in hsts_issues(resp.headers[HSTS])]
        return [
            make_finding(
                self.name,
                vuln_class,
                vuln_class,
                title=issue.title,
                description=issue.description,
                severity=issue.severity,
                url=target.base_url,
                parameter=f"{header}/{issue.key}",
                evidence=f"{header}: {resp.headers[header][:200]}",
                remediation=issue.remediation,
                tags=["missing_hsts" if header == HSTS else "missing_security_headers"],
                raw_data=tech_headers(resp),
            )
            for header, vuln_class, issue in issues
        ]

    def _check_server_banner(
        self, resp: ScopedResponse, target: Target
    ) -> list[Finding]:
        """Server and X-Powered-By headers that disclose product versions."""
        findings: list[Finding] = []
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        if server and _VERSIONED_BANNER.search(server):
            findings.append(
                make_finding(
                    self.name,
                    "banner",
                    "banner_disclosure",
                    title="Server header discloses version information",
                    description=(
                        f"The Server header contains version details: '{server}'. "
                        f"This helps attackers identify known vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    url=target.base_url,
                    parameter="Server",
                    evidence=f"Server: {server}",
                    remediation="Remove version details from the Server header.",
                    tags=["security_misconfiguration"],
                    raw_data=tech_headers(resp),
                )
            )
        if powered:
            findings.append(
                make_finding(
                    self.name,
                    "banner",
                    "banner_disclosure",
                    title="X-Powered-By header present",
                    description=(
                        f"The X-Powered-By header reveals: '{powered}'. "
                        f"This discloses technology stack information."
                    ),
                    severity=Severity.LOW,
                    url=target.base_url,
                    parameter="X-Powered-By",
                    evidence=f"X-Powered-By: {powered}",
                    remediation="Remove the X-Powered-By header.",
                    tags=["security_misconfiguration"],
                    raw_data=tech_headers(resp),
                )
            )
        return findings
