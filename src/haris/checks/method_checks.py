from ..models import Finding, Severity, Target
from ..net import ScopedClient
from .findings import make_finding
from .probe_scanner import ProbeScanner
from .requesting import try_request

RISKY_METHODS = ("PUT", "DELETE", "PATCH", "CONNECT")
TRACE_MARKER = "haris-trace-probe"


class HttpMethodScanner(ProbeScanner):
    """Risky verbs advertised by OPTIONS and a live TRACE echo."""

    name = "method_checks"
    version = "1.0.0"
    description = "HTTP methods: OPTIONS advertisement and TRACE"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        return [*self._options(client, target), *self._trace(client, target)]

    def _options(self, client: ScopedClient, target: Target) -> list[Finding]:
        resp = try_request(client, "OPTIONS", target.base_url)
        if resp is None:
            return []
        allow = resp.headers.get("Allow") or resp.headers.get("Public") or ""
        listed = {m.strip().upper() for m in allow.split(",")}
        risky = [m for m in RISKY_METHODS if m in listed]
        if not risky:
            return []
        return [
            make_finding(
                self.name,
                "options_methods",
                "http_methods",
                title=f"Risky HTTP methods advertised: {', '.join(risky)}",
                description=(
                    f"OPTIONS {target.base_url} lists {', '.join(risky)} in its "
                    f"Allow header. Write verbs on a public site are rarely intended."
                ),
                severity=Severity.LOW,
                url=target.base_url,
                evidence=f"Allow: {allow}",
                request_example=f"curl -X OPTIONS -i {target.base_url}",
                remediation="Disable the verbs the application does not use.",
                tags=["security_misconfiguration"],
            )
        ]

    def _trace(self, client: ScopedClient, target: Target) -> list[Finding]:
        resp = try_request(
            client, "TRACE", target.base_url, headers={"X-Haris-Probe": TRACE_MARKER}
        )
        if resp is None or not 200 <= resp.status_code < 300:
            return []
        if TRACE_MARKER not in resp.text:
            return []
        return [
            make_finding(
                self.name,
                "trace_enabled",
                "http_trace",
                title="HTTP TRACE method is enabled",
                description=(
                    f"TRACE {target.base_url} echoed the request headers back, "
                    f"which can expose headers that scripts cannot read."
                ),
                severity=Severity.LOW,
                url=target.base_url,
                evidence=f"HTTP {resp.status_code}; echoed header {TRACE_MARKER}",
                request_example=f"curl -X TRACE -i {target.base_url}",
                remediation="Disable TRACE (for example TraceEnable off in Apache).",
                tags=["security_misconfiguration"],
            )
        ]
