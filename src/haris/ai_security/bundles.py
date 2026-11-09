import re
from dataclasses import dataclass
from urllib.parse import urljoin

from ..checks.requesting import try_request
from ..net import ScopedClient, ScopedResponse
from .discovery import origin_of

SCRIPT_SRC = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*(?:["']([^"']+)["']|([^\s>"']+))""", re.I
)
MAX_SCRIPTS = 8


@dataclass(frozen=True, eq=False)
class Asset:
    """The landing page or one same-origin script, fetched fresh for this run."""

    url: str
    response: ScopedResponse

    @property
    def text(self) -> str:
        return self.response.text


def _fetch_ok(client: ScopedClient, url: str) -> ScopedResponse | None:
    resp = try_request(client, "GET", url)
    return resp if resp is not None and 200 <= resp.status_code < 300 else None


def collect_assets(client: ScopedClient, base_url: str) -> list[Asset]:
    """The landing page and its first same-origin scripts."""
    page = _fetch_ok(client, base_url)
    if page is None:
        return []
    assets = [Asset(base_url, page)]
    origin = origin_of(base_url)
    sources = dict.fromkeys(
        urljoin(base_url, quoted or bare)
        for quoted, bare in SCRIPT_SRC.findall(page.text)
    )
    for url in [u for u in sources if origin_of(u) == origin][:MAX_SCRIPTS]:
        script = _fetch_ok(client, url)
        if script is not None:
            assets.append(Asset(url, script))
    return assets
