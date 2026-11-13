from urllib.parse import quote, urljoin, urlsplit

from ..models import Finding, Severity, Target
from ..net import ScopedClient, ScopedResponse
from .findings import make_finding
from .probe_scanner import ProbeScanner
from .requesting import try_request

# .invalid never resolves (RFC 2606); the scope guard also refuses to follow it.
CANARY_HOST = "haris-redirect-canary.invalid"
CANARY_URL = f"https://{CANARY_HOST}/"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
PARAMETERS = (
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnUrl",
    "return_to",
    "continue",
    "dest",
    "destination",
    "goto",
    "target",
    "to",
)
PATHS = ("/", "/login", "/logout", "/redirect")


def _redirects_to_canary(resp: ScopedResponse | None) -> bool:
    if resp is None or resp.status_code not in REDIRECT_STATUSES:
        return False
    location = urljoin(resp.url, resp.headers.get("Location", ""))
    return urlsplit(location).hostname == CANARY_HOST


class OpenRedirectScanner(ProbeScanner):
    """Redirect parameters that send the browser to an attacker-chosen host."""

    name = "redirect_checks"
    version = "1.0.0"
    description = "Open redirect via common redirect parameters"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for path in PATHS:
            base = f"{target.base_url}{path}"
            every = "&".join(f"{p}={quote(CANARY_URL, safe='')}" for p in PARAMETERS)
            if not _redirects_to_canary(try_request(client, "GET", f"{base}?{every}")):
                continue
            for param in PARAMETERS:
                probe_url = f"{base}?{param}={quote(CANARY_URL, safe='')}"
                if _redirects_to_canary(try_request(client, "GET", probe_url)):
                    findings.append(self._finding(base, param, probe_url))
        return findings

    def _finding(self, url: str, param: str, probe_url: str) -> Finding:
        return make_finding(
            self.name,
            "open_redirect",
            "open_redirect",
            title=f"Open redirect via '{param}' parameter",
            description=(
                f"{url} redirects to a host named in the '{param}' parameter, so "
                f"a crafted link can send users to an attacker's site."
            ),
            severity=Severity.MEDIUM,
            url=url,
            parameter=param,
            evidence=f"{param}={CANARY_URL} produced a redirect to {CANARY_HOST}",
            request_example=f"curl -i '{probe_url}'",
            remediation=(
                "Redirect only to relative paths or to an allow-list of hosts."
            ),
            tags=["open_redirect"],
        )
