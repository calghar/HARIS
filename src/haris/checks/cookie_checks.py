from typing import Any

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Finding, ScanContext, ScannerResult, Severity, Target
from ..net import NetworkError
from .cookie_policy import (
    FRAMEWORK_SESSIONS,
    NAME_KEY,
    is_public_suffix,
    is_session_cookie,
    lifetime_seconds,
    parse_set_cookie,
)
from .findings import make_finding
from .requesting import fetch_page, scan_client

MAX_SAFE_LIFETIME_SECONDS = 365 * 24 * 60 * 60
SECONDS_PER_DAY = 86_400


@register_check
class CookieSecurityScanner(BaseScanner):
    """Flag weak attributes on session cookies set by the target's front page.

    Only cookies that look like login sessions are judged (see ``cookie_policy``);
    analytics, preference and anti-forgery cookies are ignored.
    """

    name = "cookie_checks"
    version = "1.1.0"
    description = "Session cookie analysis (flags, scope, expiry, naming)"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault(
            "max_cookie_lifetime_seconds", MAX_SAFE_LIFETIME_SECONDS
        )

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        with scan_client(target, context) as client:
            try:
                resp = fetch_page(client, target.base_url)
            except NetworkError as exc:
                result.errors.append(f"{type(exc).__name__}: {exc}")
                return result
        result.raw_output = str(dict(resp.headers))
        for raw in resp.set_cookies:
            attrs = parse_set_cookie(raw)
            if attrs and is_session_cookie(attrs[NAME_KEY]):
                result.findings.extend(self._analyse_cookie(attrs, target))
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _cookie_finding(
        self,
        name: str,
        target: Target,
        *,
        kind: str,
        vuln_class: str,
        title: str,
        description: str,
        severity: Severity,
        evidence: str,
        remediation: str,
    ) -> Finding:
        return make_finding(
            self.name,
            kind,
            vuln_class,
            title=title,
            description=description,
            severity=severity,
            url=target.base_url,
            parameter=name,
            evidence=evidence,
            remediation=remediation,
            tags=["security_misconfiguration"],
        )

    def _analyse_cookie(self, attrs: dict[str, str], target: Target) -> list[Finding]:
        name = attrs[NAME_KEY]
        findings: list[Finding] = []
        if target.scheme == "https" and "secure" not in attrs:
            findings.append(
                self._cookie_finding(
                    name,
                    target,
                    kind="session_flag",
                    vuln_class="cookie_missing_secure",
                    title=f"Cookie '{name}' missing Secure flag",
                    description=(
                        f"The session cookie '{name}' on {target.base_url} does not "
                        f"carry the Secure attribute, so a browser sends it over "
                        f"plain HTTP and exposes it to network eavesdroppers."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Set-Cookie: {name}=...; (no Secure flag)",
                    remediation=f"Set-Cookie: {name}=<value>; Secure; ...",
                )
            )
        if "httponly" not in attrs:
            findings.append(
                self._cookie_finding(
                    name,
                    target,
                    kind="session_flag",
                    vuln_class="cookie_missing_httponly",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    description=(
                        f"The session cookie '{name}' on {target.base_url} is not "
                        f"HttpOnly, so any script on the page (including injected "
                        f"XSS) can read it through document.cookie."
                    ),
                    severity=Severity.LOW,
                    evidence=f"Set-Cookie: {name}=...; (no HttpOnly flag)",
                    remediation=f"Set-Cookie: {name}=<value>; HttpOnly; ...",
                )
            )
        findings.extend(self._check_samesite(attrs, target))
        findings.extend(self._check_domain(attrs, target))
        findings.extend(self._check_lifetime(attrs, target))
        framework = FRAMEWORK_SESSIONS.get(name.lower())
        if framework:
            findings.append(
                self._cookie_finding(
                    name,
                    target,
                    kind="name_disclosure",
                    vuln_class="cookie_name_disclosure",
                    title=f"Predictable session cookie '{name}' reveals {framework}",
                    description=(
                        f"'{name}' is the default session cookie name of {framework}, "
                        f"which tells an observer the back-end technology."
                    ),
                    severity=Severity.INFO,
                    evidence=f"Set-Cookie: {name}=...",
                    remediation=(
                        "Rename the session cookie to a generic name through the "
                        "framework's session configuration."
                    ),
                )
            )
        return findings

    def _check_samesite(self, attrs: dict[str, str], target: Target) -> list[Finding]:
        name = attrs[NAME_KEY]
        value = attrs.get("samesite")
        if value is not None and value.lower() not in {"none", ""}:
            return []
        if value is None:
            title = f"Cookie '{name}' missing SameSite attribute"
            description = (
                f"The session cookie '{name}' on {target.base_url} has no SameSite "
                f"attribute; older browsers send it cross-site, which raises CSRF risk."
            )
            severity = Severity.LOW
            evidence = f"Set-Cookie: {name}=...; (no SameSite attribute)"
        else:
            secure = "secure" in attrs
            title = f"Cookie '{name}' uses weak SameSite=None"
            description = (
                f"The session cookie '{name}' on {target.base_url} is sent in all "
                f"cross-site requests (SameSite=None)."
                + ("" if secure else " The Secure flag is also absent.")
            )
            severity = Severity.LOW if secure else Severity.MEDIUM
            evidence = f"Set-Cookie: {name}=...; SameSite=None"
        return [
            self._cookie_finding(
                name,
                target,
                kind="session_attribute",
                vuln_class="cookie_samesite",
                title=title,
                description=description,
                severity=severity,
                evidence=evidence,
                remediation=(
                    f"Set SameSite=Strict or Lax on '{name}' unless cross-site "
                    f"delivery is required; SameSite=None also needs Secure."
                ),
            )
        ]

    def _check_domain(self, attrs: dict[str, str], target: Target) -> list[Finding]:
        name = attrs[NAME_KEY]
        domain = attrs.get("domain", "").strip()
        if not domain:
            return []
        host = target.hostname
        bare = domain.lstrip(".")
        if is_public_suffix(domain):
            title = f"Cookie '{name}' has overly broad Domain: {domain}"
            description = (
                f"The session cookie '{name}' sets Domain='{domain}', a public "
                f"suffix; a browser sends it to every host under that suffix."
            )
            severity = Severity.HIGH
        elif bare != host and host.endswith(f".{bare}"):
            title = f"Cookie '{name}' Domain is broader than the target host"
            description = (
                f"The session cookie '{name}' is set with Domain='{domain}' while "
                f"the target host is '{host}', so all of '{bare}' receives it."
            )
            severity = Severity.INFO
        else:
            return []
        return [
            self._cookie_finding(
                name,
                target,
                kind="session_attribute",
                vuln_class="cookie_scope",
                title=title,
                description=description,
                severity=severity,
                evidence=f"Set-Cookie: {name}=...; Domain={domain}",
                remediation=(
                    f"Omit the Domain attribute of '{name}' or set it to '{host}'."
                ),
            )
        ]

    def _check_lifetime(self, attrs: dict[str, str], target: Target) -> list[Finding]:
        name = attrs[NAME_KEY]
        lifetime = lifetime_seconds(attrs)
        limit = self.options["max_cookie_lifetime_seconds"]
        if lifetime is None or lifetime <= limit:
            return []
        days, limit_days = lifetime // SECONDS_PER_DAY, limit // SECONDS_PER_DAY
        source = (
            f"Max-Age={attrs['max-age']}"
            if "max-age" in attrs
            else f"Expires={attrs.get('expires', 'unknown')}"
        )
        return [
            self._cookie_finding(
                name,
                target,
                kind="session_attribute",
                vuln_class="cookie_lifetime",
                title=f"Cookie '{name}' has excessive expiry ({days} days)",
                description=(
                    f"The session cookie '{name}' on {target.base_url} lives {days} "
                    f"days ({source}); the recommended maximum is {limit_days} days."
                ),
                severity=Severity.LOW,
                evidence=f"Set-Cookie: {name}=...; {source}",
                remediation=(
                    f"Limit the lifetime of '{name}' to {limit_days} days and "
                    f"expire sessions on the server."
                ),
            )
        ]
