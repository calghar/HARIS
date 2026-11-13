import logging
from typing import Any

from ..core.scanner import BaseScanner
from ..core.vuln_class import slug
from ..models import Finding, ScanContext, ScannerResult, Severity, Target
from ..net import NetworkError, ScopedClient
from .findings import make_finding
from .info_patterns import (
    DEBUG_ENDPOINTS,
    ERROR_INDICATORS,
    HTML_COMMENT,
    SENSITIVE_COMMENT_PATTERNS,
    VERSION_ENDPOINTS,
)
from .path_probe import PathHit, probe_paths
from .requesting import fetch_page, is_html, scan_client, try_request

logger = logging.getLogger(__name__)

ERROR_PROBE_PATHS = ("/____nonexistent____", "/%00", "/'")
COMMENT_EXCERPT_CHARS = 200
EVIDENCE_PREVIEW_CHARS = 300
CONTEXT_CHARS = 80


class InfoDisclosureScanner(BaseScanner):
    """Information disclosure: error pages, debug and version endpoints, comments."""

    name = "info_disclosure"
    version = "1.1.0"
    description = (
        "Information disclosure checks (error pages, debug endpoints, comments)"
    )

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("check_error_pages", True)
        self.options.setdefault("check_debug_endpoints", True)
        self.options.setdefault("check_html_comments", True)
        self.options.setdefault("check_version_endpoints", True)
        # Maximum response body to inspect (characters)
        self.options.setdefault("max_body_bytes", 50_000)

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        with scan_client(target, context) as client:
            try:
                if self.options["check_error_pages"]:
                    result.findings.extend(self._check_error_pages(client, target))
                if self.options["check_debug_endpoints"]:
                    result.findings.extend(self._check_debug_endpoints(client, target))
                if self.options["check_html_comments"]:
                    result.findings.extend(self._check_html_comments(client, target))
                if self.options["check_version_endpoints"]:
                    result.findings.extend(
                        self._check_version_endpoints(client, target)
                    )
            except NetworkError as exc:
                result.errors.append(f"{type(exc).__name__}: {exc}")
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _check_error_pages(self, client: ScopedClient, target: Target) -> list[Finding]:
        """Provoke 4xx/5xx responses and look for stack traces or framework details."""
        findings: list[Finding] = []
        seen: set[str] = set()
        for path in ERROR_PROBE_PATHS:
            url = target.base_url + path
            resp = try_request(client, "GET", url)
            if resp is None or resp.status_code < 400:
                continue
            body = resp.text[: self.options["max_body_bytes"]]
            for pattern, label, severity in ERROR_INDICATORS:
                match = None if label in seen else pattern.search(body)
                if match is None:
                    continue
                seen.add(label)
                start = max(0, match.start() - CONTEXT_CHARS)
                snippet = body[start : match.end() + CONTEXT_CHARS].strip()
                findings.append(
                    make_finding(
                        self.name,
                        "verbose_error",
                        "verbose_error",
                        title=f"Verbose error page: {label}",
                        description=(
                            f"A {resp.status_code} response from {url} "
                            f"contains '{label}', which may aid an attacker "
                            f"in fingerprinting the application stack."
                        ),
                        severity=severity,
                        url=url,
                        parameter=slug(label),
                        evidence=f"Matched: {match.group(0)!r}\nContext: {snippet!r}",
                        request_example=f"GET {url}",
                        remediation=(
                            "Configure the application to return generic "
                            "error pages in production. Disable debug mode "
                            "and suppress framework-level exception details."
                        ),
                        tags=["verbose_errors", "security_misconfiguration"],
                    )
                )
        return findings

    def _check_debug_endpoints(
        self, client: ScopedClient, target: Target
    ) -> list[Finding]:
        """Probe management paths; the baseline and validators decide what is real."""
        endpoints = {path: (desc, sev) for path, desc, sev in DEBUG_ENDPOINTS}
        findings: list[Finding] = []
        for hit in probe_paths(client, target.base_url, endpoints):
            description, severity = endpoints[hit.path]
            findings.append(
                self._path_finding(
                    hit,
                    kind="debug_endpoint",
                    vuln_class="sensitive_file",
                    title=f"Exposed debug endpoint: {hit.path}",
                    description=(
                        f"{description} at {hit.url} is publicly accessible "
                        f"(HTTP {hit.response.status_code}). Debug and management "
                        f"endpoints should not be reachable in production."
                    ),
                    severity=severity,
                    remediation=(
                        f"Restrict access to {hit.path} via firewall rules, "
                        "authentication middleware, or by disabling the endpoint "
                        "entirely in production deployments."
                    ),
                    tags=["verbose_errors", "security_misconfiguration"],
                )
            )
        return findings

    def _check_html_comments(
        self, client: ScopedClient, target: Target
    ) -> list[Finding]:
        """Scan the root page's HTML comments for markers and credential-like text."""
        resp = fetch_page(client, target.base_url)
        if resp.status_code >= 400 or not is_html(resp):
            return []
        body = resp.text[: self.options["max_body_bytes"]]
        findings: list[Finding] = []
        reported: set[str] = set()
        for comment in HTML_COMMENT.findall(body):
            for pattern, label, severity in SENSITIVE_COMMENT_PATTERNS:
                if label in reported or not pattern.search(comment):
                    continue
                reported.add(label)
                excerpt = comment.strip()[:COMMENT_EXCERPT_CHARS]
                findings.append(
                    make_finding(
                        self.name,
                        "html_comment",
                        "html_comment_leak",
                        title=f"Sensitive keyword in HTML comment: {label}",
                        description=(
                            f"An HTML comment on {target.base_url} contains "
                            f"'{label}'. Source-code comments visible to the "
                            f"browser may leak internal details, credentials, "
                            f"or developer notes."
                        ),
                        severity=severity,
                        url=target.base_url,
                        parameter=slug(label),
                        evidence=f"Comment (truncated): <!-- {excerpt} -->",
                        remediation=(
                            "Remove or sanitise HTML comments before deploying "
                            "to production. Use a build step that strips "
                            "comments from HTML output."
                        ),
                        tags=["verbose_errors", "security_misconfiguration"],
                    )
                )
        return findings

    def _check_version_endpoints(
        self, client: ScopedClient, target: Target
    ) -> list[Finding]:
        """Probe /version style paths; the body must contain a version number."""
        endpoints = dict(VERSION_ENDPOINTS)
        findings: list[Finding] = []
        for hit in probe_paths(client, target.base_url, endpoints):
            findings.append(
                self._path_finding(
                    hit,
                    kind="version_endpoint",
                    vuln_class="version_disclosure",
                    title=f"Version information exposed at {hit.path}",
                    description=(
                        f"{endpoints[hit.path]} ({hit.url}) returned "
                        f"HTTP {hit.response.status_code} with a version number. "
                        f"Exposing software versions lets attackers match "
                        f"known CVEs."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        f"Restrict or remove {hit.path}. If a version endpoint is "
                        "required for health-check tooling, protect it with "
                        "authentication or IP allowlisting."
                    ),
                    tags=["security_misconfiguration"],
                )
            )
        return findings

    def _path_finding(
        self, hit: PathHit, *, kind: str, vuln_class: str, **fields: Any
    ) -> Finding:
        resp = hit.response
        preview = resp.text[:EVIDENCE_PREVIEW_CHARS].strip()
        return make_finding(
            self.name,
            f"{kind}_validated" if hit.verdict.validated else kind,
            vuln_class,
            url=hit.url,
            evidence=(
                f"HTTP {resp.status_code}, Content-Length: {len(resp.content)}, "
                f"Preview: {preview!r}"
            ),
            request_example=f"GET {hit.url}",
            **fields,
        )
