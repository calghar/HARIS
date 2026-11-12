import logging
import weakref
from collections.abc import Iterator
from contextlib import contextmanager

from ..models import ScanContext, Target
from ..net import (
    ScopedClient,
    ScopedResponse,
    ScopeViolation,
    SSRFBlocked,
    TransportError,
)

logger = logging.getLogger(__name__)

# Failures that end one probe; RequestBudgetExceeded is left to stop the check.
PROBE_ERRORS = (ScopeViolation, SSRFBlocked, TransportError)
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})

_PAGES: weakref.WeakKeyDictionary[ScopedClient, dict[str, ScopedResponse]] = (
    weakref.WeakKeyDictionary()
)


@contextmanager
def scan_client(target: Target, context: ScanContext | None) -> Iterator[ScopedClient]:
    """The scan-wide client, or a private one when a check runs standalone."""
    shared = getattr(context, "http", None)
    if shared is not None:
        yield shared
        return
    with ScopedClient(target) as client:
        yield client


def try_request(
    client: ScopedClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
    timeout_s: float | None = None,
) -> ScopedResponse | None:
    """Send one probe; ``None`` when scope, SSRF guard or transport refuses it."""
    try:
        return client.request(
            method, url, headers=headers, body=body, timeout_s=timeout_s
        )
    except PROBE_ERRORS as exc:
        logger.debug("%s %s skipped: %s", method, url, exc)
        return None


def fetch_page(client: ScopedClient, url: str) -> ScopedResponse:
    """GET *url* once per scan; later checks reuse the response."""
    pages = _PAGES.setdefault(client, {})
    if url not in pages:
        pages[url] = client.get(url)
    return pages[url]


def media_type(resp: ScopedResponse) -> str:
    return resp.headers.get("content-type", "").split(";")[0].strip().lower()


def is_html(resp: ScopedResponse) -> bool:
    return media_type(resp) in HTML_TYPES
