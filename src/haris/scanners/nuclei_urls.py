import logging
from urllib.parse import urlsplit

from ..models import Target
from ..models.scan_context import ScanContext
from ..net.errors import SSRFBlocked
from ..net.scoped_client import ScopedClient
from ..net.ssrf import vet_host

logger = logging.getLogger(__name__)

_DEFAULT_PORTS = {"http": 80, "https": 443}
_SCHEMES = frozenset(_DEFAULT_PORTS)


def filter_discovered_urls(target: Target, context: ScanContext, cap: int) -> list[str]:
    """Base URL plus in-scope vetted URLs of its origin; empty when only the base."""
    if not context.discovered_urls:
        return []
    urls = [target.base_url]
    seen = {target.base_url}
    for url in context.discovered_urls:
        if url in seen or not _admitted(target, context, url):
            continue
        urls.append(url)
        seen.add(url)
    if len(urls) <= 1:
        return []
    return urls[:cap]


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parts = urlsplit(url)
    try:
        port = parts.port or _DEFAULT_PORTS.get(parts.scheme)
    except ValueError:
        port = None
    return parts.scheme, parts.hostname, port


def _admitted(target: Target, context: ScanContext, url: str) -> bool:
    scheme, host, port = _origin(url)
    if scheme not in _SCHEMES or not host or port is None:
        return False
    if (scheme, host, port) != _origin(target.base_url):
        return False
    if not target.scope.is_url_in_scope(url):
        return False
    client = context.http
    if not isinstance(client, ScopedClient):
        return False
    try:
        vet_host(
            host,
            port,
            allow_private=client.policy.allow_private,
            resolver=client.resolver,
        )
    except SSRFBlocked:
        logger.info("dropped discovered url host %s", host)
        return False
    return True
