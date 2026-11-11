import random
from collections.abc import Mapping

RETRY_STATUSES = frozenset({502, 503, 504})
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 0.5
BACKOFF_JITTER_S = 0.25
RETRY_AFTER_CAP_S = 60.0


def backoff(attempt: int) -> float:
    return BACKOFF_BASE_S * 2.0 ** (attempt - 1) + random.uniform(0, BACKOFF_JITTER_S)


def retry_after(headers: Mapping[str, str], attempt: int) -> float:
    """Seconds to wait after a 429: ``Retry-After`` capped, else the backoff."""
    try:
        return min(float(headers["retry-after"]), RETRY_AFTER_CAP_S)
    except (KeyError, ValueError):
        return backoff(attempt)
