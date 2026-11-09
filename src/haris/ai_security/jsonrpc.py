import json
from typing import Any

from ..net import ScopedResponse

JSON_RPC_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
EVENT_STREAM = "text/event-stream"


def rpc_request(
    method: str, request_id: int | None, params: dict[str, Any] | None = None
) -> str:
    """A JSON-RPC 2.0 request body; ``request_id=None`` makes it a notification."""
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        body["id"] = request_id
    if params is not None:
        body["params"] = params
    return json.dumps(body)


def media_type(resp: ScopedResponse) -> str:
    return resp.headers.get("content-type", "").split(";")[0].strip().lower()


def parse_rpc(resp: ScopedResponse) -> dict[str, Any] | None:
    """The JSON-RPC object of a JSON or event-stream reply, else ``None``."""
    if media_type(resp) == EVENT_STREAM:
        payloads = [
            line[5:].strip()
            for line in resp.text.splitlines()
            if line.startswith("data:")
        ]
    else:
        payloads = [resp.text]
    for payload in payloads:
        try:
            body = json.loads(payload)
        except ValueError:
            continue
        if isinstance(body, dict) and body.get("jsonrpc") == "2.0":
            return body
    return None


def rpc_result(resp: ScopedResponse | None) -> dict[str, Any] | None:
    """The ``result`` object of a successful JSON-RPC reply."""
    if resp is None or not 200 <= resp.status_code < 300:
        return None
    body = parse_rpc(resp)
    result = body.get("result") if body else None
    return result if isinstance(result, dict) else None
