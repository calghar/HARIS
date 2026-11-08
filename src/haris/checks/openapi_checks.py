import json
from typing import Any

from ..core.decorators import register_check
from ..models import Finding, Severity, Target
from ..net import ScopedClient
from .findings import make_finding
from .path_probe import PathHit, probe_paths
from .probe_scanner import ProbeScanner

SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
)


def _operation_count(hit: PathHit) -> int:
    try:
        document: Any = json.loads(hit.response.text)
        return len(document.get("paths", {}))
    except (ValueError, AttributeError):
        return 0


@register_check
class OpenApiScanner(ProbeScanner):
    """OpenAPI and Swagger documents served without authentication."""

    name = "openapi_checks"
    version = "1.0.0"
    description = "Exposed OpenAPI/Swagger specification documents"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        return [
            self._finding(hit)
            for hit in probe_paths(client, target.base_url, SPEC_PATHS)
            if hit.verdict.validated
        ]

    def _finding(self, hit: PathHit) -> Finding:
        count = _operation_count(hit)
        return make_finding(
            self.name,
            "spec_exposed",
            "api_docs_exposed",
            title=f"API specification exposed: {hit.path}",
            description=(
                f"{hit.url} serves an OpenAPI/Swagger document describing "
                f"{count} paths. It lists every endpoint and parameter an "
                f"attacker can target."
            ),
            severity=Severity.LOW,
            url=hit.url,
            evidence=f"HTTP {hit.response.status_code}, {count} paths, "
            f"validated: {hit.verdict.reason} ({hit.verdict.span})",
            request_example=f"curl -s {hit.url}",
            remediation=(
                "Require authentication for API documentation, or serve it only "
                "in non-production environments."
            ),
            tags=["security_misconfiguration"],
        )
