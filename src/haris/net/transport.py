import requests
from pydantic import BaseModel, ConfigDict, Field
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

READ_CHUNK_BYTES = 8192


class PinnedAdapter(HTTPAdapter):
    """Connects to a vetted IP while TLS SNI and the certificate check use *host*."""

    def __init__(self, host: str) -> None:
        self._host = host
        super().__init__()

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: object
    ) -> None:
        pool_kwargs["server_hostname"] = self._host
        pool_kwargs["assert_hostname"] = self._host
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


class ScopedResponse(BaseModel):
    """Response handed to callers; the body is capped by the network policy."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    status_code: int
    url: str
    headers: CaseInsensitiveDict[str]
    set_cookies: list[str] = Field(default_factory=list)
    content: bytes = b""
    request_id: str = ""
    elapsed_ms: float = 0.0
    redirect_blocked: bool = False
    redirect_chain: list[str] = Field(default_factory=list)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


def read_capped(response: requests.Response, limit: int) -> bytes:
    """Read at most *limit* bytes of a streamed response, then close it."""
    chunks: list[bytes] = []
    size = 0
    try:
        for chunk in response.iter_content(READ_CHUNK_BYTES):
            chunks.append(chunk)
            size += len(chunk)
            if size >= limit:
                break
    finally:
        response.close()
    return b"".join(chunks)[:limit]


def set_cookie_values(response: requests.Response) -> list[str]:
    """Every Set-Cookie header (requests folds duplicates into one string)."""
    raw = getattr(response.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return list(raw.getlist("Set-Cookie"))
    value = response.headers.get("Set-Cookie")
    return [value] if value else []
