import logging
import re
from typing import Any
from urllib.parse import urljoin

import requests

from ..core.decorators import handle_scanner_errors, register_check
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)

# Debug / management endpoints that should never be publicly reachable
DEBUG_ENDPOINTS: list[tuple[str, str, Severity]] = [
    ("/debug", "Generic debug endpoint", Severity.HIGH),
    ("/trace", "Trace endpoint", Severity.HIGH),
    ("/_debug_toolbar", "Django Debug Toolbar", Severity.HIGH),
    ("/actuator", "Spring Boot Actuator root", Severity.HIGH),
    ("/actuator/env", "Spring Boot Actuator /env", Severity.CRITICAL),
    ("/actuator/dump", "Spring Boot Actuator /dump", Severity.HIGH),
    ("/health", "Health-check endpoint (informational)", Severity.LOW),
    ("/info", "Info endpoint (informational)", Severity.LOW),
    ("/metrics", "Metrics endpoint", Severity.MEDIUM),
    ("/swagger-ui", "Swagger UI", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI (legacy path)", Severity.MEDIUM),
    ("/api-docs", "OpenAPI / Swagger JSON", Severity.MEDIUM),
    ("/v2/api-docs", "Springfox Swagger v2 docs", Severity.MEDIUM),
    ("/v3/api-docs", "Springfox Swagger v3 docs", Severity.MEDIUM),
]

# Version-disclosure endpoints
VERSION_ENDPOINTS: list[tuple[str, str]] = [
    ("/version", "Version endpoint"),
    ("/api/version", "API version endpoint"),
    ("/app/version", "App version endpoint"),
]

# Patterns in error-page body text that indicate verbose stack traces or
# framework leakage.  Matches are case-insensitive.
ERROR_INDICATORS: list[tuple[str, str, Severity]] = [
    # Stack-trace indicators
    (r"Traceback \(most recent call last\)", "Python stack trace", Severity.HIGH),
    (
        r"at\s+[\w\.]+\([\w\.]+\.(?:java|kt):\d+\)",
        "Java/Kotlin stack trace",
        Severity.HIGH,
    ),
    (r"System\.Web\.HttpException", "ASP.NET exception class", Severity.HIGH),
    (
        r"Microsoft\.CSharp\.|System\.Web\.",
        ".NET namespace in error response",
        Severity.MEDIUM,
    ),
    # Framework version disclosure
    (r"Django[\s/][\d\.]+", "Django version disclosure", Severity.MEDIUM),
    (r"Laravel[\s/][\d\.]+", "Laravel version disclosure", Severity.MEDIUM),
    (r"Ruby on Rails[\s/][\d\.]+", "Rails version disclosure", Severity.MEDIUM),
    (r"Express[\s/][\d\.]+", "Express.js version disclosure", Severity.MEDIUM),
    (r"Flask[\s/][\d\.]+", "Flask version disclosure", Severity.MEDIUM),
    (r"Spring[\s/][\d\.]+", "Spring version disclosure", Severity.MEDIUM),
    # Explicit debug-mode markers
    (r"DEBUG\s*=\s*True", "Django DEBUG=True in response", Severity.HIGH),
    (r"SQLSTATE\[", "Raw SQL error / SQLSTATE code", Severity.HIGH),
    (r"ORA-\d{5}", "Oracle database error code", Severity.HIGH),
    (r"com\.mysql\.jdbc\.", "MySQL JDBC driver class in response", Severity.HIGH),
    (r"Caused by:\s+\w", "Java 'Caused by' exception chain", Severity.HIGH),
    # Internal paths
    (
        r"/home/\w+/|/var/www/|/srv/",
        "Internal filesystem path disclosed",
        Severity.MEDIUM,
    ),
    (
        r"C:\\(?:Users|inetpub|Windows)\\",
        "Windows filesystem path disclosed",
        Severity.MEDIUM,
    ),
]

# HTML comment patterns that suggest leaked sensitive content.
SENSITIVE_COMMENT_PATTERNS: list[tuple[str, str]] = [
    (r"TODO", "TODO comment"),
    (r"FIXME", "FIXME comment"),
    (r"HACK", "HACK comment"),
    (r"password", "password keyword"),
    (r"secret", "secret keyword"),
    (r"\bkey\b", "key keyword"),
    (r"\btoken\b", "token keyword"),
    (r"api[_-]?key", "API key reference"),
    (r"private", "private keyword"),
    (r"internal", "internal comment"),
]

# Compiled pattern to extract all HTML comments
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


@register_check
class InfoDisclosureScanner(BaseScanner):
    """Detect information disclosure vulnerabilities via HTTP.

    Runs four sub-checks:

    1. **Error pages** -- sends a request designed to provoke a 4xx/5xx
       response and looks for stack traces, framework details, or debug info
       in the body.
    2. **Debug endpoints** -- probes a curated list of management/debug paths
       and flags any that return HTTP 200.
    3. **HTML comment leakage** -- fetches the root page and scans HTML
       comments for sensitive keywords (TODO, password, token, etc.).
    4. **Version endpoints** -- checks paths like ``/version`` and
       ``/api/version`` for software version strings.

    No external tools are required; only the ``requests`` library is used.
    """

    name = "info_disclosure"
    version = "1.0.0"
    description = (
        "Information disclosure checks (error pages, debug endpoints, comments)"
    )

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 15)
        self.options.setdefault("check_error_pages", True)
        self.options.setdefault("check_debug_endpoints", True)
        self.options.setdefault("check_html_comments", True)
        self.options.setdefault("check_version_endpoints", True)
        # Maximum response body to inspect (bytes) -- avoids reading huge files
        self.options.setdefault("max_body_bytes", 50_000)

    @handle_scanner_errors
    def scan(self, target: Target, context: Any = None) -> ScannerResult:  # noqa: ARG002
        """Run all information-disclosure sub-checks against *target*.

        Args:
            target: The scan target, including scope and auth configuration.

        Returns:
            A :class:`~HARIS.core.scanner.ScannerResult` populated with
            any findings discovered during the scan.
        """
        result = ScannerResult(scanner_name=self.name)
        session = requests.Session()
        session.headers.update(target.auth.as_headers())

        if self.options["check_error_pages"]:
            result.findings.extend(self._check_error_pages(session, target))

        if self.options["check_debug_endpoints"]:
            result.findings.extend(self._check_debug_endpoints(session, target))

        if self.options["check_html_comments"]:
            result.findings.extend(self._check_html_comments(session, target))

        if self.options["check_version_endpoints"]:
            result.findings.extend(self._check_version_endpoints(session, target))

        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Not used -- findings are created inline during scan()."""
        return []

    def _check_error_pages(
        self, session: requests.Session, target: Target
    ) -> list[Finding]:
        """Trigger error responses and inspect the body for leakage.

        Two probes are used:
        - A path that almost certainly does not exist (``/____nonexistent____``)
          to provoke a 404 with verbose framework error output.
        - A malformed query string appended to the root to provoke 400/500
          errors in some frameworks.

        Args:
            session: Authenticated requests session.
            target:  Scan target.

        Returns:
            Findings for each distinct error-indicator pattern detected.
        """
        findings: list[Finding] = []
        probe_urls: list[str] = [
            urljoin(target.base_url + "/", "____nonexistent____"),
            target.base_url + "/%00",  # null-byte -- triggers some frameworks
            target.base_url + "/'",  # single-quote -- triggers SQL errors
        ]

        seen_patterns: set[str] = set()

        for url in probe_urls:
            if not target.scope.is_url_in_scope(url):
                continue

            try:
                resp = session.get(
                    url,
                    timeout=self.options["timeout"],
                    allow_redirects=True,
                    verify=True,
                )
            except requests.RequestException as exc:
                logger.debug("Error-page probe failed for %s: %s", url, exc)
                continue

            # Only inspect bodies where the server generated an error
            if resp.status_code < 400:
                continue

            body = resp.text[: self.options["max_body_bytes"]]

            for pattern, label, severity in ERROR_INDICATORS:
                if pattern in seen_patterns:
                    continue  # already reported this pattern from a previous probe

                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    seen_patterns.add(pattern)
                    snippet = body[
                        max(0, match.start() - 80) : match.end() + 80
                    ].strip()
                    findings.append(
                        Finding(
                            title=f"Verbose error page: {label}",
                            description=(
                                f"A {resp.status_code} response from {url} "
                                f"contains '{label}', which may aid an attacker "
                                f"in fingerprinting the application stack."
                            ),
                            severity=severity,
                            confidence=Confidence.CONFIRMED,
                            url=url,
                            evidence=(
                                f"Matched: {match.group(0)!r}\nContext: {snippet!r}"
                            ),
                            request_example=f"GET {url}",
                            remediation=(
                                "Configure the application to return generic "
                                "error pages in production. Disable debug mode "
                                "and suppress framework-level exception details."
                            ),
                            scanner=self.name,
                            tags=["verbose_errors", "security_misconfiguration"],
                        )
                    )

        return findings

    def _check_debug_endpoints(
        self, session: requests.Session, target: Target
    ) -> list[Finding]:
        """Probe known debug and management paths for public accessibility.

        Each endpoint in :data:`DEBUG_ENDPOINTS` is requested; a 200 response
        is treated as a confirmed finding.  Redirects are not followed so that
        login-redirected endpoints are not false-positively flagged.

        Args:
            session: Authenticated requests session.
            target:  Scan target.

        Returns:
            One finding per publicly accessible debug endpoint.
        """
        findings: list[Finding] = []

        for path, description, severity in DEBUG_ENDPOINTS:
            url = urljoin(target.base_url + "/", path.lstrip("/"))

            if not target.scope.is_url_in_scope(url):
                logger.debug("Skipping out-of-scope debug endpoint: %s", url)
                continue

            try:
                resp = session.get(
                    url,
                    timeout=self.options["timeout"],
                    allow_redirects=False,
                    verify=True,
                )
            except requests.RequestException as exc:
                logger.debug("Debug endpoint probe failed for %s: %s", url, exc)
                continue

            if resp.status_code != 200:
                continue

            # Peek at the first portion of the response body for evidence
            preview = resp.text[:300].strip()

            findings.append(
                Finding(
                    title=f"Exposed debug endpoint: {path}",
                    description=(
                        f"{description} at {url} is publicly accessible "
                        f"(HTTP {resp.status_code}). Debug and management "
                        f"endpoints should not be reachable in production."
                    ),
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    url=url,
                    evidence=(
                        f"HTTP {resp.status_code}, "
                        f"Content-Length: {len(resp.content)}, "
                        f"Preview: {preview!r}"
                    ),
                    request_example=f"GET {url}",
                    remediation=(
                        f"Restrict access to {path} via firewall rules, "
                        "authentication middleware, or by disabling the endpoint "
                        "entirely in production deployments."
                    ),
                    scanner=self.name,
                    tags=["verbose_errors", "security_misconfiguration"],
                )
            )

        return findings

    def _check_html_comments(
        self, session: requests.Session, target: Target
    ) -> list[Finding]:
        """Scan the root page's HTML for comments with sensitive keywords.

        Fetches the root URL and extracts all HTML comments
        (``<!-- ... -->``).  Any comment that matches a sensitive keyword
        pattern is reported.

        Args:
            session: Authenticated requests session.
            target:  Scan target.

        Returns:
            One finding per distinct sensitive-keyword hit across all comments.
        """
        findings: list[Finding] = []

        if not target.scope.is_url_in_scope(target.base_url):
            return findings

        try:
            resp = session.get(
                target.base_url,
                timeout=self.options["timeout"],
                allow_redirects=True,
                verify=True,
            )
        except requests.RequestException as exc:
            logger.warning("HTML comment check failed: %s", exc)
            return findings

        if resp.status_code >= 400:
            return findings

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            return findings

        body = resp.text[: self.options["max_body_bytes"]]
        comments = _HTML_COMMENT_RE.findall(body)

        if not comments:
            return findings

        # Track which keyword labels have already been reported
        reported_labels: set[str] = set()

        for comment in comments:
            for pattern, label in SENSITIVE_COMMENT_PATTERNS:
                if label in reported_labels:
                    continue

                if re.search(pattern, comment, re.IGNORECASE):
                    reported_labels.add(label)
                    # Truncate the comment to avoid leaking secrets in reports
                    safe_comment = comment.strip()[:200]
                    findings.append(
                        Finding(
                            title=f"Sensitive keyword in HTML comment: {label}",
                            description=(
                                f"An HTML comment on {target.base_url} contains "
                                f"the keyword '{label}'. Source-code comments "
                                f"visible to the browser may leak internal details, "
                                f"credentials, or developer notes."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            url=target.base_url,
                            evidence=f"Comment (truncated): <!-- {safe_comment} -->",
                            remediation=(
                                "Remove or sanitise HTML comments before deploying "
                                "to production. Use a build step that strips "
                                "comments from HTML output."
                            ),
                            scanner=self.name,
                            tags=["verbose_errors", "security_misconfiguration"],
                        )
                    )

        return findings

    def _check_version_endpoints(
        self, session: requests.Session, target: Target
    ) -> list[Finding]:
        """Probe version-disclosure endpoints.

        Requests paths like ``/version`` and ``/api/version``.  A 200
        response is reported as a potential information-disclosure issue
        because version strings help attackers identify software with known
        CVEs.

        Args:
            session: Authenticated requests session.
            target:  Scan target.

        Returns:
            One finding per accessible version endpoint.
        """
        findings: list[Finding] = []

        for path, description in VERSION_ENDPOINTS:
            url = urljoin(target.base_url + "/", path.lstrip("/"))

            if not target.scope.is_url_in_scope(url):
                continue

            try:
                resp = session.get(
                    url,
                    timeout=self.options["timeout"],
                    allow_redirects=False,
                    verify=True,
                )
            except requests.RequestException as exc:
                logger.debug("Version endpoint probe failed for %s: %s", url, exc)
                continue

            if resp.status_code != 200:
                continue

            preview = resp.text[:200].strip()

            findings.append(
                Finding(
                    title=f"Version information exposed at {path}",
                    description=(
                        f"{description} ({url}) returned HTTP 200. "
                        f"Exposing software version numbers enables attackers "
                        f"to quickly identify applicable CVEs and exploits."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    url=url,
                    evidence=(
                        f"HTTP {resp.status_code}, "
                        f"Content-Length: {len(resp.content)}, "
                        f"Response: {preview!r}"
                    ),
                    request_example=f"GET {url}",
                    remediation=(
                        f"Restrict or remove {path}. If a version endpoint is "
                        "required for health-check tooling, protect it with "
                        "authentication or IP allowlisting."
                    ),
                    scanner=self.name,
                    tags=["outdated_server", "security_misconfiguration"],
                )
            )

        return findings
