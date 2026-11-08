import itertools
import threading
from collections import deque

from pydantic import BaseModel, Field

from ..models import EvidenceExchange
from ..models.verification import EXCERPT_LIMIT


class LogEntry(BaseModel):
    """One sent request; headers are redacted before they get here."""

    request_id: str
    method: str
    url: str
    status: int = 0
    elapsed_ms: float = 0.0
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_excerpt: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: str = ""
    error: str = ""

    def to_exchange(self, role: str = "probe") -> EvidenceExchange:
        """Evidence form of this entry; ``request_id`` links back to the log."""
        return EvidenceExchange.model_validate(
            {**self.model_dump(exclude={"error"}), "role": role}
        )


def excerpt(body: bytes) -> str:
    """Decode the first 8 KiB of *body* for logging and evidence."""
    return body[:EXCERPT_LIMIT].decode("utf-8", errors="replace")[:EXCERPT_LIMIT]


class RequestLog:
    """Thread-safe ring buffer of the requests one scan sent."""

    def __init__(self, capacity: int = 5000) -> None:
        self._entries: deque[LogEntry] = deque(maxlen=capacity)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def next_id(self) -> str:
        with self._lock:
            return f"req-{next(self._ids):06d}"

    def add(self, entry: LogEntry) -> None:
        with self._lock:
            self._entries.append(entry)

    def get(self, request_id: str) -> LogEntry | None:
        with self._lock:
            return next((e for e in self._entries if e.request_id == request_id), None)

    def entries(self) -> list[LogEntry]:
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
