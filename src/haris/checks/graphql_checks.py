import json
from typing import Any
from urllib.parse import quote

from ..models import Finding, Severity, Target
from ..net import ScopedClient, ScopedResponse
from .findings import make_finding
from .probe_scanner import ProbeScanner
from .requesting import try_request

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/query")
INTROSPECTION_QUERY = "{__schema{queryType{name} types{name}}}"
JSON_HEADERS = {"Content-Type": "application/json"}
# Apollo Server rejects simple GET queries that lack a preflight-forcing header.
GET_HEADERS = {"Apollo-Require-Preflight": "true"}


def _schema_types(resp: ScopedResponse | None) -> list[str] | None:
    """Type names from an introspection answer, or ``None`` when it is not one."""
    if resp is None or not 200 <= resp.status_code < 300:
        return None
    try:
        body: Any = json.loads(resp.text)
    except ValueError:
        return None
    schema = body.get("data", {}).get("__schema") if isinstance(body, dict) else None
    if not isinstance(schema, dict) or not isinstance(schema.get("types"), list):
        return None
    return [str(t.get("name")) for t in schema["types"] if isinstance(t, dict)]


class GraphqlIntrospectionScanner(ProbeScanner):
    """GraphQL endpoints that answer a schema introspection query."""

    name = "graphql_checks"
    version = "1.0.0"
    description = "GraphQL introspection enabled"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for path in GRAPHQL_PATHS:
            url = f"{target.base_url}{path}"
            post = try_request(
                client,
                "POST",
                url,
                headers=JSON_HEADERS,
                body=json.dumps({"query": INTROSPECTION_QUERY}),
            )
            types = _schema_types(post)
            if types is None:
                get_url = f"{url}?query={quote(INTROSPECTION_QUERY)}"
                types = _schema_types(
                    try_request(client, "GET", get_url, headers=GET_HEADERS)
                )
            if types is not None:
                findings.append(self._finding(url, types))
        return findings

    def _finding(self, url: str, types: list[str]) -> Finding:
        return make_finding(
            self.name,
            "introspection",
            "graphql_introspection",
            title="GraphQL introspection is enabled",
            description=(
                f"{url} returned its full schema ({len(types)} types) to an "
                f"unauthenticated introspection query, which maps the API for "
                f"an attacker."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=f"__schema types: {', '.join(types[:10])}",
            request_example=(
                f"curl -s -X POST -H 'Content-Type: application/json' "
                f'-d \'{{"query":"{INTROSPECTION_QUERY}"}}\' {url}'
            ),
            remediation="Disable introspection outside development environments.",
            tags=["security_misconfiguration"],
        )
