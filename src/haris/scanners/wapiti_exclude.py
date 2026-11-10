import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PLAIN_PATH = re.compile(r"[\w/.\-]*")
REGEX_WILDCARD = ".*"
WAPITI_WILDCARD = "*"


def wapiti_exclude_urls(base_url: str, excluded_paths: list[str]) -> list[str]:
    """Convert scope regexes to absolute Wapiti URLs; skip what cannot be one."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls: list[str] = []
    for entry in excluded_paths:
        wildcard = entry.endswith(REGEX_WILDCARD)
        stem = entry.removesuffix(REGEX_WILDCARD)
        if not PLAIN_PATH.fullmatch(stem):
            logger.warning(
                "Skipping excluded path %r: Wapiti cannot take a regex", entry
            )
            continue
        path = stem if stem.startswith("/") else f"/{stem}"
        urls.append(f"{origin}{path}{WAPITI_WILDCARD if wildcard else ''}")
    return urls
