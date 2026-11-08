import logging
from typing import Any

import requests

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)

# Expected security headers and their check logic
HEADER_CHECKS: list[dict[str, Any]] = [
    {
        "header": "Strict-Transport-Security",
        "tag": "missing_hsts",
        "severity": Severity.MEDIUM,
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "remediation": (
            "Add the header: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
    },
    {
        "header": "Content-Security-Policy",
        "tag": "missing_security_headers",
        "severity": Severity.MEDIUM,
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
        "title": "Missing X-Content-Type-Options header",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "X-Frame-Options",
        "tag": "missing_security_headers",
        "severity": Severity.LOW,
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
        "title": "Missing Referrer-Policy header",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "tag": "missing_security_headers",
        "severity": Severity.LOW,
        "title": "Missing Permissions-Policy header",
        "remediation": (
            "Add a Permissions-Policy header to restrict browser features "
            "(camera, microphone, geolocation, etc.)."
        ),
    },
    {
        "header": "X-XSS-Protection",
        "tag": "missing_security_headers",
        "severity": Severity.INFO,
        "title": "Missing X-XSS-Protection header",
        "remediation": (
            "While modern browsers rely on CSP instead, adding "
            "X-XSS-Protection: 0 is the current best practice to "
            "avoid legacy XSS auditor issues."
        ),
    },
]


@register_check
class SecurityHeaderScanner(BaseScanner):
    """Check for missing or misconfigured HTTP security headers.

    This scanner issues a single GET request to the target and inspects
    the response headers.  No external tools required.
    """

    name = "header_checks"
    version = "1.0.0"
    description = "HTTP security header analysis"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 30)
        self.options.setdefault("follow_redirects", True)

    def scan(self, target: Target, context: Any = None) -> ScannerResult:  # noqa: ARG002
        result = ScannerResult(scanner_name=self.name)

        try:
            resp = requests.get(
                target.base_url,
                timeout=self.options.get("timeout", 30),
                allow_redirects=self.options.get("follow_redirects", True),
                headers=target.auth.as_headers(),
                verify=True,
            )
        except requests.RequestException as exc:
            result.errors.append(f"HTTP request failed: {exc}")
            return result

        result.raw_output = str(dict(resp.headers))
        result.findings = self._check_headers(resp, target)
        result.findings.extend(self._check_cookies(resp, target))
        result.findings.extend(self._check_server_banner(resp, target))

        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        # Not used -- findings are created inline during scan
        return []

    def _check_headers(self, resp: requests.Response, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        for check in HEADER_CHECKS:
            header_name = check["header"]
            value = resp.headers.get(header_name)

            if not value:
                findings.append(
                    Finding(
                        title=check["title"],
                        description=(
                            f"The response from {target.base_url} does not "
                            f"include the {header_name} header."
                        ),
                        severity=check["severity"],
                        confidence=Confidence.CONFIRMED,
                        url=target.base_url,
                        remediation=check["remediation"],
                        scanner=self.name,
                        tags=[check["tag"]],
                    )
                )

        return findings

    def _check_cookies(self, resp: requests.Response, target: Target) -> list[Finding]:
        """Check cookie security flags."""
        findings: list[Finding] = []

        for cookie in resp.cookies:
            if not cookie.secure:
                findings.append(
                    Finding(
                        title=f"Cookie '{cookie.name}' missing Secure flag",
                        description=(
                            f"The cookie '{cookie.name}' is set without the "
                            f"Secure flag, meaning it can be sent over HTTP."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        url=target.base_url,
                        remediation="Set the Secure flag on all cookies.",
                        scanner=self.name,
                        tags=["security_misconfiguration"],
                    )
                )

            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append(
                    Finding(
                        title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                        description=(
                            f"The cookie '{cookie.name}' is set without the "
                            f"HttpOnly flag, making it accessible to JavaScript."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        url=target.base_url,
                        remediation="Set the HttpOnly flag on session cookies.",
                        scanner=self.name,
                        tags=["security_misconfiguration"],
                    )
                )

        return findings

    def _check_server_banner(
        self, resp: requests.Response, target: Target
    ) -> list[Finding]:
        """Check if the Server header leaks version info."""
        findings: list[Finding] = []
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")

        if server and any(c.isdigit() for c in server):
            findings.append(
                Finding(
                    title="Server header discloses version information",
                    description=(
                        f"The Server header contains version details: '{server}'. "
                        f"This helps attackers identify known vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    url=target.base_url,
                    evidence=f"Server: {server}",
                    remediation="Remove version details from the Server header.",
                    scanner=self.name,
                    tags=["security_misconfiguration"],
                )
            )

        if x_powered:
            findings.append(
                Finding(
                    title="X-Powered-By header present",
                    description=(
                        f"The X-Powered-By header reveals: '{x_powered}'. "
                        f"This discloses technology stack information."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    url=target.base_url,
                    evidence=f"X-Powered-By: {x_powered}",
                    remediation="Remove the X-Powered-By header.",
                    scanner=self.name,
                    tags=["security_misconfiguration"],
                )
            )

        return findings
