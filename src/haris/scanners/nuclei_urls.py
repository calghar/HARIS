import logging
from urllib.parse import urlsplit

from ..models import Target
from ..models.scan_context import ScanContext
from ..net.errors import SSRFBlocked
from ..net.scoped_client import ScopedClient
from ..net.ssrf import vet_host

logger = logging.getLogger(__name__)

_SCHEMES = frozenset({"http", "https"})


def filter_discovered_urls(target: Target, context: ScanContext, cap: int) -> list[str]:
    """Base URL plus in-scope vetted URLs; empty when only the base remains."""
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


def _admitted(target: Target, context: ScanContext, url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in _SCHEMES:
        return False
    host = parts.hostname
    if not host or not target.scope.is_url_in_scope(url):
        return False
    client = context.http
    if not isinstance(client, ScopedClient):
        return False
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
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
