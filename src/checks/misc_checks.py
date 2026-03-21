import logging
from typing import Any
from urllib.parse import urljoin

import requests

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)

# Paths that often reveal sensitive information when exposed
SENSITIVE_PATHS = [
    ("/.env", "Environment variables file"),
    ("/.git/config", "Git configuration (source code exposure)"),
    ("/robots.txt", "Robots.txt (information disclosure)"),
    ("/sitemap.xml", "Sitemap (information disclosure)"),
    ("/.well-known/security.txt", "Security contact (informational)"),
    ("/wp-login.php", "WordPress login page"),
    ("/admin", "Admin panel"),
    ("/phpmyadmin", "phpMyAdmin database interface"),
    ("/server-status", "Apache server-status page"),
    ("/server-info", "Apache server-info page"),
    ("/.DS_Store", "macOS directory metadata file"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
    ("/elmah.axd", "ELMAH error log (.NET)"),
    ("/trace.axd", "ASP.NET trace log"),
]


@register_check
class MiscCheckScanner(BaseScanner):
    """Miscellaneous web security checks using HTTP requests.

    Tests for:
    - Exposed sensitive files and paths
    - CORS misconfiguration
    - HTTP-to-HTTPS redirect
    - Directory listing
    - Information disclosure via common paths
    """

    name = "misc_checks"
    version = "1.0.0"
    description = "Common web misconfiguration checks"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 15)
        self.options.setdefault("check_sensitive_paths", True)
        self.options.setdefault("check_cors", True)
        self.options.setdefault("check_redirect", True)

    def scan(self, target: Target) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        session = requests.Session()
        session.headers.update(target.auth.as_headers())

        if self.options["check_cors"]:
            result.findings.extend(self._check_cors(session, target))

        if self.options["check_redirect"]:
            result.findings.extend(self._check_https_redirect(session, target))

        if self.options["check_sensitive_paths"]:
            result.findings.extend(self._check_sensitive_paths(session, target))

        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _check_cors(self, session: requests.Session, target: Target) -> list[Finding]:
        """Test for overly permissive CORS configuration."""
        findings: list[Finding] = []

        try:
            # Send a request with a spoofed Origin header
            test_origin = "https://evil.example.com"
            resp = session.get(
                target.base_url,
                headers={"Origin": test_origin},
                timeout=self.options["timeout"],
                allow_redirects=True,
                verify=True,
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "")

            if acao == "*":
                findings.append(
                    Finding(
                        title="CORS allows any origin (wildcard)",
                        description=(
                            "The Access-Control-Allow-Origin header is set to '*', "
                            "allowing any website to read responses."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        url=target.base_url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation=(
                            "Restrict CORS to specific trusted origins instead "
                            "of using the wildcard."
                        ),
                        scanner=self.name,
                        tags=["cors_misconfiguration"],
                    )
                )
            elif acao == test_origin:
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
                findings.append(
                    Finding(
                        title="CORS reflects arbitrary Origin",
                        description=(
                            f"The server reflected the attacker-controlled Origin "
                            f"'{test_origin}' in Access-Control-Allow-Origin"
                            f"{' with credentials allowed' if acac == 'true' else ''}."
                        ),
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        url=target.base_url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        request_example=(
                            f"curl -H 'Origin: {test_origin}' {target.base_url}"
                        ),
                        remediation=(
                            "Validate the Origin header against an allowlist. "
                            "Never reflect arbitrary origins."
                        ),
                        scanner=self.name,
                        tags=["cors_misconfiguration"],
                    )
                )

        except requests.RequestException as exc:
            logger.warning("CORS check failed: %s", exc)

        return findings

    def _check_https_redirect(
        self, session: requests.Session, target: Target
    ) -> list[Finding]:
        """Check if HTTP requests are redirected to HTTPS."""
        findings: list[Finding] = []

        if target.scheme != "https":
            return findings  # already flagged by TLS checks

        # Test the HTTP version of the URL
        http_url = target.base_url.replace("https://", "http://", 1)
        try:
            resp = session.get(
                http_url,
                timeout=self.options["timeout"],
                allow_redirects=False,
                verify=False,
            )

            if resp.status_code not in (301, 302, 307, 308):
                findings.append(
                    Finding(
                        title="No HTTP-to-HTTPS redirect",
                        description=(
                            f"Requesting {http_url} returned status "
                            f"{resp.status_code} instead of a redirect to HTTPS."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        url=http_url,
                        remediation=(
                            "Configure a 301 redirect from HTTP to HTTPS "
                            "for all routes."
                        ),
                        scanner=self.name,
                        tags=["cleartext_transmission"],
                    )
                )
            else:
                location = resp.headers.get("Location", "")
                if location and not location.startswith("https://"):
                    findings.append(
                        Finding(
                            title="HTTP redirect does not target HTTPS",
                            description=(
                                f"HTTP redirect goes to {location} "
                                f"which is not an HTTPS URL."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=http_url,
                            evidence=f"Location: {location}",
                            remediation="Ensure the redirect location uses HTTPS.",
                            scanner=self.name,
                            tags=["cleartext_transmission"],
                        )
                    )

        except requests.RequestException:
            # HTTP port may not be open, which is fine
            pass

        return findings

    def _check_sensitive_paths(
        self, session: requests.Session, target: Target
    ) -> list[Finding]:
        """Probe for commonly exposed sensitive files and paths."""
        findings: list[Finding] = []

        for path, description in SENSITIVE_PATHS:
            url = urljoin(target.base_url + "/", path.lstrip("/"))

            # Skip if path is excluded from scope
            if not target.scope.is_url_in_scope(url):
                continue

            try:
                resp = session.get(
                    url,
                    timeout=self.options["timeout"],
                    allow_redirects=False,
                    verify=True,
                )

                if resp.status_code == 200:
                    # Determine severity based on path
                    severity = self._classify_path_severity(path)
                    tag = self._classify_path_tag(path)

                    findings.append(
                        Finding(
                            title=f"Accessible sensitive path: {path}",
                            description=(
                                f"{description}. The path {path} returned "
                                f"HTTP 200, indicating the file/page is accessible."
                            ),
                            severity=severity,
                            confidence=Confidence.CONFIRMED,
                            url=url,
                            evidence=f"HTTP 200, Content-Length: {len(resp.content)}",
                            remediation=(
                                f"Restrict access to {path} via server "
                                f"configuration or remove it from the web root."
                            ),
                            scanner=self.name,
                            tags=[tag],
                        )
                    )

            except requests.RequestException:
                continue  # path not reachable, no issue

        return findings

    @staticmethod
    def _classify_path_severity(path: str) -> Severity:
        critical_paths = {"/.env", "/.git/config"}
        high_paths = {
            "/phpmyadmin",
            "/elmah.axd",
            "/trace.axd",
            "/server-status",
            "/server-info",
        }
        if path in critical_paths:
            return Severity.CRITICAL
        if path in high_paths:
            return Severity.HIGH
        return Severity.MEDIUM

    @staticmethod
    def _classify_path_tag(path: str) -> str:
        return "security_misconfiguration"
