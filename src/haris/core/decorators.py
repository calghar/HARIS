import functools
import logging
import time
from collections.abc import Callable
from typing import Any

from ..models import ScannerResult
from .scanner import BaseScanner

logger = logging.getLogger(__name__)


def scanner_registry() -> dict[str, type[BaseScanner]]:
    """Return the built-in scanner map (a copy)."""
    # Inside the body: scanners and checks import this module (a top-level cycle).
    from ..scanners import SCANNER_REGISTRY

    return dict(SCANNER_REGISTRY)


def check_registry() -> dict[str, type[BaseScanner]]:
    """Return the built-in check map (a copy), including ``ai_security``."""
    # ai_security imports checks, so CHECK_REGISTRY cannot list it.
    from ..ai_security import AiSecurityScanner
    from ..checks import CHECK_REGISTRY

    return {AiSecurityScanner.name: AiSecurityScanner, **CHECK_REGISTRY}


def all_registered() -> dict[str, type[BaseScanner]]:
    """Merged dict of every scanner and check."""
    return {**scanner_registry(), **check_registry()}


# Method / function decorators


def timed[F: Callable[..., Any]](func: F) -> F:
    """Log the wall-clock time of a function call.

    Works on both sync functions and methods.  Logs at DEBUG level.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.monotonic()
        try:
            return func(*args, **kwargs)
        finally:
            elapsed = time.monotonic() - start
            logger.debug(
                "%s.%s completed in %.2fs",
                func.__module__,
                func.__qualname__,
                elapsed,
            )

    return wrapper  # type: ignore[return-value]


def handle_scanner_errors[F: Callable[..., Any]](func: F) -> F:
    """Wrap a scanner's ``scan()`` method to catch exceptions.

    If the wrapped method raises, the exception is logged and an
    empty ``ScannerResult`` with the error message is returned so
    the engine can continue with remaining scanners.
    """

    @functools.wraps(func)
    def wrapper(self: BaseScanner, *args: Any, **kwargs: Any) -> ScannerResult:
        try:
            result: ScannerResult = func(self, *args, **kwargs)
            return result
        except Exception as exc:
            logger.exception(
                "Scanner %s raised %s: %s", self.name, type(exc).__name__, exc
            )
            return ScannerResult(
                scanner_name=self.name,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

    return wrapper  # type: ignore[return-value]
