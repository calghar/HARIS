from typing import Any
from urllib.parse import urljoin

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Finding, ScanContext, ScannerResult, Severity, Target
from ..net import NetworkError, ScopedClient, ScopedResponse
from .findings import make_finding
from .path_probe import probe_paths
from .requesting import scan_client, try_request

TEST_ORIGIN = "https://evil.example.com"
REDIRECT_STATUSES = frozenset({301, 302, 307, 308})

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
CRITICAL_PATHS = frozenset({"/.env", "/.git/config"})
HIGH_PATHS = frozenset(
    {"/phpmyadmin", "/elmah.axd", "/trace.axd", "/server-status", "/server-info"}
)
INFO_PATHS = frozenset({"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"})


def _first_hop(resp: ScopedResponse, request_url: str) -> str:
    """Where the first response redirected to; empty when it did not redirect."""
    if resp.redirect_chain:
        return resp.redirect_chain[0]
    if resp.status_code in REDIRECT_STATUSES:
        return urljoin(request_url, resp.headers.get("Location", ""))
    return ""


@register_check
class MiscCheckScanner(BaseScanner):
    """CORS, HTTP-to-HTTPS redirect and exposed sensitive paths."""

    name = "misc_checks"
    version = "1.1.0"
    description = "Common web misconfiguration checks"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("check_sensitive_paths", True)
        self.options.setdefault("check_cors", True)
        self.options.setdefault("check_redirect", True)

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        with scan_client(target, context) as client:
            try:
                if self.options["check_cors"]:
                    result.findings.extend(self._check_cors(client, target))
                if self.options["check_redirect"]:
                    result.findings.extend(self._check_https_redirect(client, target))
                if self.options["check_sensitive_paths"]:
                    result.findings.extend(self._check_sensitive_paths(client, target))
            except NetworkError as exc:
                result.errors.append(f"{type(exc).__name__}: {exc}")
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _check_cors(self, client: ScopedClient, target: Target) -> list[Finding]:
        """Test for overly permissive CORS configuration."""
        resp = try_request(
            client, "GET", target.base_url, headers={"Origin": TEST_ORIGIN}
        )
        if resp is None:
            return []
        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            return [
                make_finding(
                    self.name,
                    "cors_wildcard",
                    "cors_misconfiguration",
                    title="CORS allows any origin (wildcard)",
                    description=(
                        "The Access-Control-Allow-Origin header is set to '*', "
                        "allowing any website to read responses."
                    ),
                    severity=Severity.MEDIUM,
                    url=target.base_url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation=(
                        "Restrict CORS to specific trusted origins instead "
                        "of using the wildcard."
                    ),
                    tags=["cors_misconfiguration"],
                )
            ]
        if acao == TEST_ORIGIN:
            credentials = (
                resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                == "true"
            )
            return [
                make_finding(
                    self.name,
                    "cors_reflected",
                    "cors_misconfiguration",
                    title="CORS reflects arbitrary Origin",
                    description=(
                        f"The server reflected the attacker-controlled Origin "
                        f"'{TEST_ORIGIN}' in Access-Control-Allow-Origin"
                        f"{' with credentials allowed' if credentials else ''}."
                    ),
                    severity=Severity.HIGH if credentials else Severity.MEDIUM,
                    url=target.base_url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    request_example=(
                        f"curl -H 'Origin: {TEST_ORIGIN}' {target.base_url}"
                    ),
                    remediation=(
                        "Validate the Origin header against an allowlist. "
                        "Never reflect arbitrary origins."
                    ),
                    tags=["cors_misconfiguration"],
                )
            ]
        return []

    def _check_https_redirect(
        self, client: ScopedClient, target: Target
    ) -> list[Finding]:
        """Check if HTTP requests are redirected to HTTPS."""
        if target.scheme != "https":
            return []  # already flagged by TLS checks

        http_url = target.base_url.replace("https://", "http://", 1)
        resp = try_request(client, "GET", http_url)
        if resp is None:
            return []  # the HTTP port may be closed, which is fine

        first_hop = _first_hop(resp, http_url)
        if not first_hop:
            return [
                make_finding(
                    self.name,
                    "https_redirect",
                    "no_https_redirect",
                    title="No HTTP-to-HTTPS redirect",
                    description=(
                        f"Requesting {http_url} returned status "
                        f"{resp.status_code} instead of a redirect to HTTPS."
                    ),
                    severity=Severity.MEDIUM,
                    url=http_url,
                    remediation=(
                        "Configure a 301 redirect from HTTP to HTTPS for all routes."
                    ),
                    tags=["cleartext_transmission"],
                )
            ]
        if not first_hop.startswith("https://"):
            return [
                make_finding(
                    self.name,
                    "https_redirect",
                    "no_https_redirect",
                    title="HTTP redirect does not target HTTPS",
                    description=(
                        f"HTTP redirect goes to {first_hop} which is not an HTTPS URL."
                    ),
                    severity=Severity.MEDIUM,
                    url=http_url,
                    evidence=f"Location: {first_hop}",
                    remediation="Ensure the redirect location uses HTTPS.",
                    tags=["cleartext_transmission"],
                )
            ]
        return []

    def _check_sensitive_paths(
        self, client: ScopedClient, target: Target
    ) -> list[Finding]:
        """Probe for exposed files; the baseline and validators gate each hit."""
        descriptions = dict(SENSITIVE_PATHS)
        findings: list[Finding] = []
        for hit in probe_paths(client, target.base_url, descriptions):
            path, verdict, resp = hit.path, hit.verdict, hit.response
            evidence = f"HTTP {resp.status_code}, Content-Length: {len(resp.content)}"
            if verdict.validated:
                evidence += f", validated: {verdict.reason} ({verdict.span})"
            basis = (
                "passed content validation"
                if verdict.validated
                else "differs from the host's not-found page"
            )
            findings.append(
                make_finding(
                    self.name,
                    "sensitive_path_validated"
                    if verdict.validated
                    else "sensitive_path",
                    "sensitive_file",
                    title=f"Accessible sensitive path: {path}",
                    description=(
                        f"{descriptions[path]}. The path {path} returned "
                        f"HTTP {resp.status_code} with content that {basis}."
                    ),
                    severity=self._classify_path_severity(path),
                    url=hit.url,
                    evidence=evidence,
                    remediation=(
                        f"Restrict access to {path} via server "
                        f"configuration or remove it from the web root."
                    ),
                    tags=["security_misconfiguration"],
                )
            )
        return findings

    @staticmethod
    def _classify_path_severity(path: str) -> Severity:
        if path in CRITICAL_PATHS:
            return Severity.CRITICAL
        if path in HIGH_PATHS:
            return Severity.HIGH
        if path in INFO_PATHS:
            return Severity.INFO
        return Severity.MEDIUM
