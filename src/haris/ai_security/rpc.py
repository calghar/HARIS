import json
from typing import Any

from .. import __version__
from ..checks.requesting import media_type
from ..net import ScopedResponse
from .signatures import load_signatures

JSON_RPC_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
EVENT_STREAM = "text/event-stream"
CLIENT_NAME = "haris"
# The only methods this module will ever put on the wire; none can change server state.
READ_ONLY_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "resources/list",
        "prompts/list",
    }
)


def rpc_request(
    method: str, request_id: int | None = None, params: dict[str, Any] | None = None
) -> str:
    """A read-only JSON-RPC 2.0 message; without *request_id* it is a notification."""
    if method not in READ_ONLY_METHODS:
        raise ValueError(f"MCP method {method!r} is not on the read-only allow-list")
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    return json.dumps(message)


def initialize_message() -> str:
    params = {
        "protocolVersion": load_signatures().mcp.protocol_version,
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": __version__},
    }
    return rpc_request("initialize", 1, params)


def parse_rpc(resp: ScopedResponse) -> dict[str, Any] | None:
    """The JSON-RPC message in *resp*, from a JSON body or the first SSE data event."""
    text = resp.text
    if media_type(resp) == EVENT_STREAM:
        payloads = [
            line.partition(":")[2].strip()
            for line in text.splitlines()
            if line.startswith("data:")
        ]
        text = next((p for p in payloads if p.startswith("{")), "")
    try:
        body = json.loads(text)
    except ValueError:
        return None
    return body if isinstance(body, dict) and body.get("jsonrpc") == "2.0" else None
