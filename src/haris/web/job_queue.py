import logging
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from ..db.jobs import Job, JobRepository, JobStatus

logger = logging.getLogger(__name__)

RESTART_ERROR = "Server stopped while the scan was running"
FAILURE_ERROR = "Scan failed; see the server log"


class CancelToken:
    """Cancellation flag whose callbacks fire when a running scan is cancelled."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancelled = False
        self._callbacks: list[Callable[[], None]] = []

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            callbacks = list(self._callbacks)
        for callback in callbacks:
            callback()

    def on_cancel(self, callback: Callable[[], None]) -> None:
        with self._lock:
            self._callbacks.append(callback)
            already = self._cancelled
        if already:
            callback()


type JobRunner = Callable[[Job, CancelToken], JobStatus]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class JobQueue:
    """DB-backed scan queue run by a bounded thread pool.

    One web process per database: running jobs owned by another worker id are
    treated as dead and marked incomplete on start.
    """

    def __init__(
        self, repo: JobRepository, run: JobRunner, max_concurrent: int
    ) -> None:
        self._repo = repo
        self._run = run
        self._max = max_concurrent
        self._worker_id = uuid.uuid4().hex
        self._lock = threading.Lock()
        self._running: dict[str, CancelToken] = {}
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=max_concurrent, thread_name_prefix="haris-scan"
        )
        for scan_id in repo.recover(self._worker_id, _now(), RESTART_ERROR):
            logger.warning("Scan %s was running when the server stopped", scan_id)

    @property
    def running_count(self) -> int:
        with self._lock:
            return len(self._running)

    def submit(
        self,
        scan_id: str,
        owner_user_id: str,
        params: dict[str, Any],
        *,
        target_url: str,
        profile_name: str,
        template_id: str,
        note: str = "",
    ) -> None:
        self._repo.enqueue(
            scan_id,
            owner_user_id,
            params,
            target_url=target_url,
            profile_name=profile_name,
            template_id=template_id,
            now=_now(),
        )
        if note:
            self._repo.keep_skip_note(scan_id, note)
        self.dispatch()

    def dispatch(self) -> None:
        """Start queued jobs until the concurrency bound is reached."""
        with self._lock:
            while not self._closed and len(self._running) < self._max:
                job = self._repo.claim_next(self._worker_id, _now())
                if job is None:
                    return
                token = CancelToken()
                self._running[job.scan_id] = token
                self._executor.submit(self._work, job, token)

    def cancel(self, scan_id: str) -> bool:
        """Cancel a queued job outright or signal a running one; False otherwise."""
        if self._repo.cancel_queued(scan_id, _now()):
            return True
        with self._lock:
            token = self._running.get(scan_id)
        if token is None:
            return False
        token.cancel()
        return True

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            tokens = list(self._running.values())
        for token in tokens:
            token.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _work(self, job: Job, token: CancelToken) -> None:
        error = ""
        try:
            status = self._run(job, token)
        except Exception:
            logger.exception("Scan %s failed", job.scan_id)
            status, error = JobStatus.FAILED, FAILURE_ERROR
        try:
            self._repo.finish(job.scan_id, status, _now(), error)
        except Exception:
            # Leave the row running; startup recover() marks other workers incomplete.
            logger.exception("Scan %s result was not saved", job.scan_id)
        finally:
            with self._lock:
                self._running.pop(job.scan_id, None)
            self.dispatch()
