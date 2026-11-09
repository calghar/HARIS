from dataclasses import dataclass, field
from typing import Any

from ..checks.requesting import try_request
from ..models import Finding, Target
from ..net import ScopedClient, ScopedResponse
from ..verify.evidence import exchange
from .discovery import Endpoint
from .findings import ai_finding
from .mcp_static import Definition, static_findings
from .rpc import JSON_RPC_HEADERS, parse_rpc, rpc_request
from .signatures import load_signatures

SESSION_HEADER = "Mcp-Session-Id"
VERSION_HEADER = "MCP-Protocol-Version"
FIRST_LIST_ID = 2
SURFACES = (("tools", "tool"), ("resources", "resource"), ("prompts", "prompt"))
SKIP_NO_POST = "POST is not an allowed method, so MCP tools were not listed"


@dataclass(frozen=True, eq=False)
class McpSurvey:
    endpoint: Endpoint
    definitions: list[Definition] = field(default_factory=list)
    tools_listed: bool = False
    list_response: ScopedResponse | None = None


def _result(resp: ScopedResponse | None) -> dict[str, Any] | None:
    message = parse_rpc(resp) if resp is not None else None
    result = message.get("result") if message else None
    return result if isinstance(result, dict) else None


def _session_headers(endpoint: Endpoint) -> dict[str, str]:
    result = _result(endpoint.response) or {}
    headers = dict(JSON_RPC_HEADERS)
    if version := result.get("protocolVersion"):
        headers[VERSION_HEADER] = str(version)
    if session := endpoint.response.headers.get(SESSION_HEADER.lower()):
        headers[SESSION_HEADER] = session
    return headers


def _list_all(
    client: ScopedClient,
    endpoint: Endpoint,
    headers: dict[str, str],
    method: str,
    key: str,
) -> tuple[list[dict[str, Any]] | None, ScopedResponse | None]:
    """Every item of a ``*/list`` call, following ``nextCursor`` up to the page cap."""
    items: list[dict[str, Any]] = []
    last: ScopedResponse | None = None
    cursor = ""
    for page in range(load_signatures().mcp.max_pages):
        body = rpc_request(
            method, FIRST_LIST_ID + page, {"cursor": cursor} if cursor else None
        )
        last = try_request(client, "POST", endpoint.url, headers=headers, body=body)
        result = _result(last)
        batch = result.get(key) if result else None
        if not isinstance(batch, list):
            return (items or None), last
        items += [i for i in batch if isinstance(i, dict)]
        cursor = str(result.get("nextCursor") or "") if result else ""
        if not cursor:
            break
    return items, last


def survey_mcp(client: ScopedClient, endpoint: Endpoint, notes: set[str]) -> McpSurvey:
    """Read-only walk of one MCP endpoint; SSE-only servers are not walked."""
    if not endpoint.signature.rpc:
        return McpSurvey(endpoint)
    if "POST" not in {m.upper() for m in client.target.scope.allowed_methods}:
        notes.add(SKIP_NO_POST)
        return McpSurvey(endpoint)
    headers = _session_headers(endpoint)
    try_request(
        client,
        "POST",
        endpoint.url,
        headers=headers,
        body=rpc_request("notifications/initialized"),
    )
    capabilities = (_result(endpoint.response) or {}).get("capabilities") or {}
    definitions: list[Definition] = []
    tools_listed = False
    list_response: ScopedResponse | None = None
    for method_key, surface in SURFACES:
        if method_key != "tools" and method_key not in capabilities:
            continue
        items, response = _list_all(
            client, endpoint, headers, f"{method_key}/list", method_key
        )
        if method_key == "tools":
            tools_listed, list_response = items is not None, response
        definitions += [Definition(surface, item) for item in items or []]
    return McpSurvey(endpoint, definitions, tools_listed, list_response)


def mcp_findings(
    client: ScopedClient, target: Target, endpoints: list[Endpoint], notes: set[str]
) -> list[Finding]:
    found: list[Finding] = []
    for endpoint in (e for e in endpoints if e.capability == "mcp"):
        survey = survey_mcp(client, endpoint, notes)
        proof = [exchange(client, endpoint.response, "probe")]
        if survey.list_response is not None and survey.tools_listed:
            proof.append(exchange(client, survey.list_response, "probe"))
        if not target.auth.as_headers():
            tools = sum(d.surface == "tool" for d in survey.definitions)
            found.append(
                ai_finding(
                    "mcp_unauthenticated",
                    url=endpoint.url,
                    method=endpoint.signature.method,
                    label=endpoint.signature.label,
                    detail=(
                        f"tools/list returned {tools} tools."
                        if survey.tools_listed
                        else ""
                    ),
                    evidence=f"{endpoint.signature.label} answered without credentials",
                    exchanges=proof,
                    digest=endpoint.signature.id,
                )
            )
        for finding in static_findings(endpoint, survey.definitions):
            finding.verification.evidence = list(proof)
            found.append(finding)
    return found
