import re
from urllib.parse import urlsplit

SEED_PATH = re.compile(r"/(?!/)\S*")


def wapiti_seed_urls(base_url: str, seed_paths: object) -> list[str]:
    """Absolute start URLs on the target origin; anything but a path raises."""
    if not isinstance(seed_paths, list):
        raise ValueError(f"seed_paths must be a list of paths, got {seed_paths!r}")
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    urls: list[str] = []
    for path in seed_paths:
        if not isinstance(path, str) or not SEED_PATH.fullmatch(path):
            raise ValueError(f"seed_paths entries must start with '/', got {path!r}")
        urls.append(f"{origin}{path}")
    return urls
