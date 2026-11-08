from ..core.decorators import register_check
from ..models import Finding, Severity, Target
from ..net import ScopedClient, ScopedResponse
from .cookie_policy import NAME_KEY, is_session_cookie, parse_set_cookie
from .findings import make_finding
from .path_probe import probe_paths
from .probe_scanner import ProbeScanner
from .requesting import fetch_page, is_html

ACCOUNT_PATHS = ("/login", "/signin", "/account", "/profile", "/dashboard", "/admin")


def _directives(resp: ScopedResponse) -> set[str]:
    value = resp.headers.get("Cache-Control", "")
    return {d.split("=")[0].strip().lower() for d in value.split(",") if d.strip()}


def _sets_session_cookie(resp: ScopedResponse) -> bool:
    for raw in resp.set_cookies:
        attrs = parse_set_cookie(raw)
        if attrs and is_session_cookie(attrs[NAME_KEY]):
            return True
    return False


@register_check
class CacheControlScanner(ProbeScanner):
    """Sensitive HTML responses that browsers or proxies may store."""

    name = "cache_checks"
    version = "1.0.0"
    description = "Cache-Control on login, account and session-setting responses"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        candidates: list[tuple[str, ScopedResponse, str]] = []
        front = fetch_page(client, target.base_url)
        if _sets_session_cookie(front):
            candidates.append((target.base_url, front, "sets a session cookie"))
        for hit in probe_paths(client, target.base_url, ACCOUNT_PATHS):
            candidates.append((hit.url, hit.response, f"is the {hit.path} page"))

        findings: list[Finding] = []
        for url, resp, why in candidates:
            if not 200 <= resp.status_code < 300 or not is_html(resp):
                continue
            if "no-store" in _directives(resp):
                continue
            header = resp.headers.get("Cache-Control", "(absent)")
            findings.append(
                make_finding(
                    self.name,
                    "sensitive_cacheable",
                    "cache_sensitive",
                    title="Sensitive response is cacheable",
                    description=(
                        f"The response from {url} {why} but its Cache-Control "
                        f"does not include no-store, so it may stay in a browser "
                        f"or shared cache."
                    ),
                    severity=Severity.LOW,
                    url=url,
                    evidence=f"Cache-Control: {header}",
                    remediation="Send Cache-Control: no-store on sensitive responses.",
                    tags=["security_misconfiguration"],
                )
            )
        return findings
