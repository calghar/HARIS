import math
import threading
import time
from collections.abc import Callable

MIN_RATE_RPS = 0.1


class TokenBucket:
    """Blocking token bucket shared by every caller of one scan.

    Capacity is ``max(1, ceil(rate))``.  Waiters reserve a slot under the lock
    and sleep outside it, so concurrent callers are served in order.
    """

    def __init__(
        self,
        rate_rps: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._rate = max(rate_rps, MIN_RATE_RPS)
        self._capacity = max(1, math.ceil(rate_rps))
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(self._capacity)
        self._updated = clock()
        self._lock = threading.Lock()

    @property
    def rate(self) -> float:
        return self._rate

    def acquire(self) -> None:
        with self._lock:
            self._refill()
            self._tokens -= 1
            wait = -self._tokens / self._rate if self._tokens < 0 else 0.0
        if wait > 0:
            self._sleep(wait)

    def halve_rate(self) -> None:
        """Slow down for the rest of the scan (after a 429)."""
        with self._lock:
            self._refill()
            self._rate = max(self._rate / 2, MIN_RATE_RPS)

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(
            self._capacity, self._tokens + (now - self._updated) * self._rate
        )
        self._updated = now
