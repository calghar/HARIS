import logging
import random
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from .settings import RuntimeSettings

logger = logging.getLogger(__name__)

RETRYABLE_CODES = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
NETWORK_ERRORS = frozenset(
    {"APIConnectionError", "APITimeoutError", "ConnectionError", "Timeout"}
)


def status_of(exc: BaseException) -> int | None:
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return status if isinstance(status, int) else None


def retry_after_seconds(
    exc: BaseException, now: datetime | None = None
) -> float | None:
    """Parse Retry-After as delta-seconds or an HTTP date."""
    headers = getattr(getattr(exc, "response", None), "headers", None)
    value = next(
        (v for k, v in dict(headers or {}).items() if str(k).lower() == "retry-after"),
        None,
    )
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        pass
    try:
        when = parsedate_to_datetime(str(value))
    except (TypeError, ValueError):
        return None
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


class Retrier:
    """Retries transient failures with jittered backoff and Retry-After."""

    def __init__(
        self,
        settings: RuntimeSettings,
        sleep: Callable[[float], None] = time.sleep,
        uniform: Callable[[float, float], float] = random.uniform,
    ) -> None:
        self._cfg = settings
        self._sleep = sleep
        self._uniform = uniform

    def delay(self, attempt: int, exc: BaseException) -> float | None:
        """Seconds to wait before the next attempt; None means give up."""
        cfg = self._cfg
        backoff = self._uniform(
            0, min(cfg.backoff_max_s, cfg.backoff_base_s * 2**attempt)
        )
        hinted = retry_after_seconds(exc)
        if hinted is None:
            return backoff
        return None if hinted > cfg.max_retry_after_s else max(hinted, backoff)

    def call[T](self, func: Callable[[], T]) -> T:
        for attempt in range(self._cfg.max_retries + 1):
            try:
                return func()
            except Exception as exc:
                transient = status_of(exc) in RETRYABLE_CODES or _is_network(exc)
                wait = self.delay(attempt, exc) if transient else None
                if wait is None or attempt == self._cfg.max_retries:
                    raise
                logger.warning(
                    "Transient LLM error (attempt %d), retrying in %.1fs: %s",
                    attempt + 1,
                    wait,
                    exc,
                )
                self._sleep(wait)
        raise AssertionError("unreachable")


def _is_network(exc: BaseException) -> bool:
    names = {cls.__name__ for cls in type(exc).__mro__}
    return bool(names & NETWORK_ERRORS)
