import logging
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import requests

from ..core.decorators import handle_scanner_errors, register_check
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)

# Maximum cookie lifetime considered "safe" (seconds)
_MAX_SAFE_LIFETIME_SECONDS: int = 365 * 24 * 60 * 60

# SameSite values considered sufficiently restrictive.
# "None" is only acceptable when Secure is also set and a real cross-site
# use-case exists; we flag it regardless as it weakens CSRF protection.
_SAMESITE_WEAK_VALUES: frozenset[str] = frozenset({"none", ""})

# Well-known session-cookie name patterns that reveal the back-end technology.
# These are informational -- they indicate a predictable/guessable session ID
# name, and may also assist fingerprinting.
_PREDICTABLE_SESSION_NAMES: list[tuple[str, str]] = [
    ("PHPSESSID",   "PHP"),
    ("JSESSIONID",  "Java EE / Tomcat"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("ASPSESSIONID", "Classic ASP"),
    ("rack.session", "Ruby Rack"),
    ("connect.sid",  "Node.js / Connect"),
    ("ci_session",   "CodeIgniter"),
    ("laravel_session", "Laravel"),
    ("django_session", "Django (non-default name variant)"),
    ("CFID",        "ColdFusion"),
    ("CFTOKEN",     "ColdFusion"),
]

_PREDICTABLE_NAME_MAP: dict[str, str] = {
    name.lower(): framework
    for name, framework in _PREDICTABLE_SESSION_NAMES
}

# TLDs considered "overly broad" for a Domain attribute.
# Any cookie whose Domain resolves to only a public suffix is flagged.
_OVERLY_BROAD_TLDS: frozenset[str] = frozenset({
    ".com", ".net", ".org", ".io", ".co", ".gov", ".edu",
    ".com.au", ".co.uk", ".co.nz", ".co.za",
})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_single_set_cookie(raw: str) -> dict[str, str] | None:
    """Parse a single raw ``Set-Cookie`` header into an attribute dict.

    Args:
        raw: The raw ``Set-Cookie`` header string.

    Returns:
        A dict mapping lowercase attribute names to values, or ``None``
        if the header is empty or unparseable.
    """
    if not raw:
        return None

    parts = [p.strip() for p in raw.split(";")]
    attrs: dict[str, str] = {}

    # The first part is always name=value
    name_value = parts[0]
    if "=" in name_value:
        cookie_name, cookie_value = name_value.split("=", 1)
        attrs["__name__"] = cookie_name.strip()
        attrs["__value__"] = cookie_value.strip()
    else:
        attrs["__name__"] = name_value.strip()
        attrs["__value__"] = ""

    for part in parts[1:]:
        if "=" in part:
            key, val = part.split("=", 1)
            attrs[key.strip().lower()] = val.strip()
        else:
            # Flag-only attribute (Secure, HttpOnly)
            attrs[part.strip().lower()] = ""

    if "__name__" not in attrs:
        return None

    return attrs


def _get_raw_set_cookie_headers(response: requests.Response) -> list[str]:
    """Retrieve raw ``Set-Cookie`` header strings from a response.

    ``response.raw.headers`` is a ``urllib3.HTTPHeaderDict`` that preserves
    duplicate headers.  Falls back to ``response.headers`` (which only
    keeps the last Set-Cookie) if the raw object is unavailable.

    Args:
        response: A completed HTTP response.

    Returns:
        A list of raw ``Set-Cookie`` header strings.
    """
    try:
        return response.raw.headers.getlist("set-cookie")
    except AttributeError:
        # Fallback: may miss duplicates but still usable
        return [response.headers.get("set-cookie", "")]


def _parse_set_cookie_headers(response: requests.Response) -> list[dict[str, str]]:
    """Extract raw ``Set-Cookie`` attributes from all response headers.

    ``requests`` merges duplicate ``Set-Cookie`` headers into a
    ``CookieJar``, which loses raw attribute strings (e.g. ``SameSite``).
    We parse the headers directly from the raw response to preserve them.

    Args:
        response: A completed HTTP response.

    Returns:
        A list of dicts, one per ``Set-Cookie`` header, mapping lowercase
        attribute names to their values (or empty string for flag-only attrs).
    """
    header_items = _get_raw_set_cookie_headers(response)
    raw_cookies: list[dict[str, str]] = []

    for raw in header_items:
        parsed = _parse_single_set_cookie(raw)
        if parsed is not None:
            raw_cookies.append(parsed)

    return raw_cookies


def _is_domain_overly_broad(domain: str) -> bool:
    """Return True if *domain* is just a public suffix with no registrable part.

    For example, ``.com`` or ``.co.uk`` would return True, while
    ``.example.com`` returns False.

    Args:
        domain: The Domain attribute value (may or may not have a leading dot).

    Returns:
        True if the domain is considered overly broad.
    """
    # Normalise: ensure leading dot for comparison
    normalised = domain if domain.startswith(".") else f".{domain}"
    return normalised.lower() in _OVERLY_BROAD_TLDS


def _cookie_lifetime_seconds(attrs: dict[str, str]) -> int | None:
    """Compute the effective lifetime of a cookie in seconds.

    Prefers ``Max-Age`` (authoritative per RFC 6265) over ``Expires``.
    Returns ``None`` for session cookies (no expiry attribute).

    Args:
        attrs: Parsed cookie attribute dict from :func:`_parse_set_cookie_headers`.

    Returns:
        Lifetime in seconds, or ``None`` if the cookie is a session cookie.
    """
    max_age_str = attrs.get("max-age", "").strip()
    if max_age_str:
        try:
            return int(max_age_str)
        except ValueError:
            logger.debug("Could not parse Max-Age: %r", max_age_str)

    expires_str = attrs.get("expires", "").strip()
    if expires_str:
        try:
            expires_dt = parsedate_to_datetime(expires_str)
            now = datetime.now(UTC)
            delta = (expires_dt - now).total_seconds()
            return max(0, int(delta))
        except Exception:
            logger.debug("Could not parse Expires: %r", expires_str)

    return None  # session cookie


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@register_check
class CookieSecurityScanner(BaseScanner):
    """Deep cookie security analysis.

    Issues a single GET request to the target's base URL and inspects
    every ``Set-Cookie`` header for the following weaknesses:

    - **Missing Secure flag** -- cookie can be sent over plain HTTP.
    - **Missing HttpOnly flag** -- cookie is accessible from JavaScript.
    - **Missing or weak SameSite attribute** -- increases CSRF risk.
    - **Overly broad Domain scope** -- cookie sent to an entire TLD.
    - **Excessive expiry** -- persistent cookies older than one year.
    - **Predictable session name** -- reveals back-end technology stack.

    All cookie attributes are extracted from the raw ``Set-Cookie`` headers
    so that ``SameSite`` (which ``requests.cookies.RequestsCookieJar`` does
    not expose) is correctly captured.
    """

    name = "cookie_checks"
    version = "1.0.0"
    description = "Deep cookie security analysis (flags, scope, expiry, naming)"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 15)
        self.options.setdefault("follow_redirects", True)
        # Override maximum safe lifetime (seconds) via options if desired
        self.options.setdefault(
            "max_cookie_lifetime_seconds", _MAX_SAFE_LIFETIME_SECONDS
        )

    @handle_scanner_errors
    def scan(self, target: Target) -> ScannerResult:
        """Run cookie security checks against *target*.

        Performs a single GET request (following redirects by default) and
        analyses every ``Set-Cookie`` header returned in the response chain.

        Args:
            target: The scan target, including scope and auth configuration.

        Returns:
            A :class:`~HARIS.core.scanner.ScannerResult` containing one
            finding per detected cookie security weakness.
        """
        result = ScannerResult(scanner_name=self.name)

        try:
            resp = requests.get(
                target.base_url,
                timeout=self.options["timeout"],
                allow_redirects=self.options["follow_redirects"],
                headers=target.auth.as_headers(),
                verify=True,
            )
        except requests.RequestException as exc:
            result.errors.append(f"HTTP request failed: {exc}")
            return result

        result.raw_output = str(dict(resp.headers))

        cookies = _parse_set_cookie_headers(resp)
        if not cookies:
            logger.debug("No Set-Cookie headers found on %s", target.base_url)
            return result

        for cookie_attrs in cookies:
            result.findings.extend(
                self._analyse_cookie(cookie_attrs, target)
            )

        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Not used -- findings are created inline during scan()."""
        return []

    # ------------------------------------------------------------------
    # Per-cookie analysis
    # ------------------------------------------------------------------

    def _analyse_cookie(
        self, attrs: dict[str, str], target: Target
    ) -> list[Finding]:
        """Run all sub-checks for a single cookie.

        Args:
            attrs: Parsed attribute dict for the cookie, as returned by
                   :func:`_parse_set_cookie_headers`.
            target: The scan target (used for URL and scope).

        Returns:
            A list of findings (may be empty if the cookie is well-configured).
        """
        findings: list[Finding] = []
        name = attrs.get("__name__", "<unknown>")
        is_https = target.scheme == "https"

        findings.extend(self._check_secure_flag(attrs, name, target, is_https))
        findings.extend(self._check_httponly_flag(attrs, name, target))
        findings.extend(self._check_samesite(attrs, name, target))
        findings.extend(self._check_domain_scope(attrs, name, target))
        findings.extend(self._check_expiry(attrs, name, target))
        findings.extend(self._check_predictable_name(name, target))

        return findings

    def _check_secure_flag(
        self,
        attrs: dict[str, str],
        name: str,
        target: Target,
        is_https: bool,
    ) -> list[Finding]:
        """Flag cookies missing the ``Secure`` attribute on HTTPS origins.

        The ``Secure`` flag only makes sense for HTTPS; we skip this check
        on plain-HTTP targets (which should be caught by the TLS scanner).

        Args:
            attrs:    Parsed cookie attributes.
            name:     Cookie name.
            target:   Scan target.
            is_https: True when the target uses HTTPS.

        Returns:
            List of findings (zero or one entry).
        """
        if not is_https:
            return []

        if "secure" not in attrs:
            return [Finding(
                title=f"Cookie '{name}' missing Secure flag",
                description=(
                    f"The cookie '{name}' on {target.base_url} does not "
                    f"carry the Secure attribute. Without this flag the "
                    f"browser will transmit the cookie over plain HTTP, "
                    f"exposing it to network eavesdroppers."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                evidence=f"Set-Cookie: {name}=...; (no Secure flag)",
                remediation=(
                    f"Add the Secure attribute to the '{name}' cookie: "
                    f"Set-Cookie: {name}=<value>; Secure; ..."
                ),
                scanner=self.name,
                tags=["security_misconfiguration"],
            )]

        return []

    def _check_httponly_flag(
        self,
        attrs: dict[str, str],
        name: str,
        target: Target,
    ) -> list[Finding]:
        """Flag cookies missing the ``HttpOnly`` attribute.

        Args:
            attrs:  Parsed cookie attributes.
            name:   Cookie name.
            target: Scan target.

        Returns:
            List of findings (zero or one entry).
        """
        if "httponly" not in attrs:
            return [Finding(
                title=f"Cookie '{name}' missing HttpOnly flag",
                description=(
                    f"The cookie '{name}' on {target.base_url} is not "
                    f"marked HttpOnly. Any JavaScript running on the page "
                    f"(including injected XSS payloads) can read its value "
                    f"via document.cookie."
                ),
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                evidence=f"Set-Cookie: {name}=...; (no HttpOnly flag)",
                remediation=(
                    f"Add HttpOnly to the '{name}' cookie: "
                    f"Set-Cookie: {name}=<value>; HttpOnly; ..."
                ),
                scanner=self.name,
                tags=["security_misconfiguration"],
            )]

        return []

    def _check_samesite(
        self,
        attrs: dict[str, str],
        name: str,
        target: Target,
    ) -> list[Finding]:
        """Check the ``SameSite`` attribute for absence or weak values.

        - **Missing SameSite** -- modern browsers default to ``Lax``, but
          explicit declaration is best practice and required for older
          browsers.
        - **SameSite=None** -- allows cross-site delivery; only acceptable
          with ``Secure`` and a legitimate cross-site use-case.

        Args:
            attrs:  Parsed cookie attributes.
            name:   Cookie name.
            target: Scan target.

        Returns:
            List of findings (zero or one entry).
        """
        samesite_value = attrs.get("samesite")

        if samesite_value is None:
            return [Finding(
                title=f"Cookie '{name}' missing SameSite attribute",
                description=(
                    f"The cookie '{name}' on {target.base_url} has no "
                    f"SameSite attribute. While modern browsers default to "
                    f"'Lax', older browsers send the cookie cross-site, "
                    f"increasing CSRF risk."
                ),
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                evidence=f"Set-Cookie: {name}=...; (no SameSite attribute)",
                remediation=(
                    f"Explicitly set SameSite on '{name}': "
                    f"Set-Cookie: {name}=<value>; SameSite=Strict (or Lax)"
                ),
                scanner=self.name,
                tags=["security_misconfiguration", "session_fixation"],
            )]

        if samesite_value.lower() in _SAMESITE_WEAK_VALUES:
            has_secure = "secure" in attrs
            severity = Severity.MEDIUM if not has_secure else Severity.LOW
            return [Finding(
                title=f"Cookie '{name}' uses weak SameSite=None",
                description=(
                    f"The cookie '{name}' on {target.base_url} is set with "
                    f"SameSite=None, which allows it to be sent in all "
                    f"cross-site requests. "
                    + (
                        "The Secure flag is also absent, which may cause "
                        "browsers to reject or silently drop the cookie."
                        if not has_secure
                        else "Ensure this is intentional for a cross-site use-case."
                    )
                ),
                severity=severity,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                evidence=(
                    f"Set-Cookie: {name}=...; SameSite=None"
                    + ("" if has_secure else " (Secure flag absent)")
                ),
                remediation=(
                    f"Change SameSite to 'Strict' or 'Lax' for '{name}' "
                    f"unless cross-site delivery is explicitly required. "
                    f"If SameSite=None is required, the Secure flag must "
                    f"also be present."
                ),
                scanner=self.name,
                tags=["security_misconfiguration", "session_fixation"],
            )]

        return []

    def _check_domain_scope(
        self,
        attrs: dict[str, str],
        name: str,
        target: Target,
    ) -> list[Finding]:
        """Flag overly broad ``Domain`` attributes.

        A ``Domain`` of ``.com`` or ``.co.uk`` would cause the browser to
        send the cookie to every site under that TLD -- an almost certainly
        unintentional configuration that can be exploited by related-domain
        cookie-injection attacks.

        Args:
            attrs:  Parsed cookie attributes.
            name:   Cookie name.
            target: Scan target.

        Returns:
            List of findings (zero or one entry).
        """
        domain = attrs.get("domain", "").strip()
        if not domain:
            return []

        if _is_domain_overly_broad(domain):
            return [Finding(
                title=f"Cookie '{name}' has overly broad Domain: {domain}",
                description=(
                    f"The cookie '{name}' on {target.base_url} sets "
                    f"Domain='{domain}', which is a public suffix. "
                    f"The browser will send this cookie to every host "
                    f"under that suffix, leaking the cookie value to "
                    f"unrelated sites."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                evidence=f"Set-Cookie: {name}=...; Domain={domain}",
                remediation=(
                    f"Change the Domain attribute of '{name}' to the full "
                    f"registrable hostname (e.g. '.example.com') or omit it "
                    f"entirely to restrict the cookie to the exact origin."
                ),
                scanner=self.name,
                tags=["security_misconfiguration", "session_fixation"],
            )]

        # Also check if the domain is broader than the target's own hostname.
        # e.g. target is app.example.com but cookie Domain is .example.com.
        # This is acceptable but worth flagging at INFO level.
        target_hostname = urlparse(target.base_url).hostname or ""
        normalised_domain = domain.lstrip(".")
        if (
            normalised_domain
            and normalised_domain != target_hostname
            and target_hostname.endswith(f".{normalised_domain}")
        ):
            return [Finding(
                title=f"Cookie '{name}' Domain is broader than the target host",
                description=(
                    f"The cookie '{name}' is set with Domain='{domain}' "
                    f"while the target host is '{target_hostname}'. "
                    f"The cookie will be sent to all subdomains under "
                    f"'{normalised_domain}', not just the issuing host."
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                url=target.base_url,
                evidence=f"Set-Cookie: {name}=...; Domain={domain}",
                remediation=(
                    f"Restrict the Domain attribute of '{name}' to "
                    f"'{target_hostname}' or remove the attribute entirely "
                    f"if cross-subdomain access is not required."
                ),
                scanner=self.name,
                tags=["security_misconfiguration"],
            )]

        return []

    def _check_expiry(
        self,
        attrs: dict[str, str],
        name: str,
        target: Target,
    ) -> list[Finding]:
        """Flag cookies with an expiry greater than the configured threshold.

        Long-lived persistent cookies increase the window of exposure if
        they are stolen or forged.  The default threshold is one year.

        Args:
            attrs:  Parsed cookie attributes.
            name:   Cookie name.
            target: Scan target.

        Returns:
            List of findings (zero or one entry).
        """
        lifetime = _cookie_lifetime_seconds(attrs)
        if lifetime is None:
            return []  # session cookie -- no expiry concern

        max_lifetime = self.options["max_cookie_lifetime_seconds"]
        if lifetime <= max_lifetime:
            return []

        lifetime_days = lifetime // 86_400
        threshold_days = max_lifetime // 86_400

        # Determine expiry source for evidence string
        expiry_source = (
            f"Max-Age={attrs['max-age']}"
            if "max-age" in attrs
            else f"Expires={attrs.get('expires', 'unknown')}"
        )

        return [Finding(
            title=f"Cookie '{name}' has excessive expiry ({lifetime_days} days)",
            description=(
                f"The cookie '{name}' on {target.base_url} expires in "
                f"{lifetime_days} days ({expiry_source}). "
                f"The recommended maximum is {threshold_days} days. "
                f"Long-lived cookies remain valid long after a session ends, "
                f"increasing the impact of theft or fixation attacks."
            ),
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            url=target.base_url,
            evidence=f"Set-Cookie: {name}=...; {expiry_source}",
            remediation=(
                f"Reduce the '{name}' cookie lifetime to at most "
                f"{threshold_days} days. For session cookies that must "
                f"persist across browser restarts, implement server-side "
                f"session expiry and renewal mechanisms."
            ),
            scanner=self.name,
            tags=["security_misconfiguration", "session_fixation"],
        )]

    def _check_predictable_name(
        self,
        name: str,
        target: Target,
    ) -> list[Finding]:
        """Flag session cookies with technology-revealing names.

        Names like ``PHPSESSID`` or ``JSESSIONID`` immediately identify the
        back-end framework, giving attackers a head-start in targeting
        known vulnerabilities.  This is an informational finding.

        Args:
            name:   Cookie name.
            name:   Cookie name.
            target: Scan target.

        Returns:
            List of findings (zero or one entry).
        """
        framework = _PREDICTABLE_NAME_MAP.get(name.lower())
        if not framework:
            return []

        return [Finding(
            title=f"Predictable session cookie name '{name}' reveals {framework}",
            description=(
                f"The cookie name '{name}' is the default session identifier "
                f"for {framework}. This immediately reveals the back-end "
                f"technology to any observer, simplifying targeted attacks "
                f"against known {framework} vulnerabilities."
            ),
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            url=target.base_url,
            evidence=f"Set-Cookie: {name}=...",
            remediation=(
                "Rename the session cookie to a generic, non-identifying "
                "name (e.g. 'sid' or 'session') via the framework's session "
                "configuration. For PHP: session_name('sid'); for "
                "Tomcat: set <Context sessionCookieName='sid'/>."
            ),
            scanner=self.name,
            tags=["security_misconfiguration", "session_fixation"],
        )]
