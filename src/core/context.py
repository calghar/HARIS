import logging
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models import ScanSession, Target

logger = logging.getLogger(__name__)


@contextmanager
def scan_context(
    target: Target,
    session_id: str | None = None,
) -> Generator[ScanSession]:
    """Context manager that wraps a complete scan lifecycle.

    Sets ``started_at`` on entry and ``finished_at`` on exit, even if
    an exception occurs.

    Usage::

        with scan_context(target) as session:
            # run scanners, append findings to session
            ...
        # session.finished_at is guaranteed to be set here
    """
    sid = session_id or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    session = ScanSession(
        session_id=sid,
        target=target,
        started_at=datetime.now(UTC).isoformat(),
    )
    logger.info("Scan session %s started for %s", sid, target.base_url)

    try:
        yield session
    finally:
        session.finished_at = datetime.now(UTC).isoformat()
        logger.info(
            "Scan session %s finished — %d findings, %.1fs",
            sid,
            len(session.all_findings),
            session.duration_seconds,
        )


@contextmanager
def temp_workspace(prefix: str = "HARIS_") -> Generator[Path]:
    """Temporary directory that is cleaned up automatically.

    Scanners that need to write intermediate files (JSON/XML reports
    from CLI tools) should use this instead of managing tempfiles
    themselves.
    """
    with tempfile.TemporaryDirectory(prefix=prefix) as tmpdir:
        path = Path(tmpdir)
        logger.debug("Temporary workspace: %s", path)
        yield path
    # directory and contents removed by TemporaryDirectory.__exit__


@contextmanager
def http_session(
    target: Target,
    *,
    pool_connections: int = 10,
    pool_maxsize: int = 10,
) -> Generator[Any]:
    """Managed ``requests.Session`` with auth headers and connection pooling.

    Ensures the session is closed cleanly and auth headers from the
    target config are applied.
    """
    import requests
    from requests.adapters import HTTPAdapter

    sess = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
    )
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update(target.auth.as_headers())

    try:
        yield sess
    finally:
        sess.close()
