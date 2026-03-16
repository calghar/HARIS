import functools
import logging
import time
from collections.abc import Callable
from typing import Any

from ..models import ScannerResult
from .scanner import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
# Global registries -- populated by decorators at import time
# ---------------------------------------------------------------
_SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}
_CHECK_REGISTRY: dict[str, type[BaseScanner]] = {}


def scanner_registry() -> dict[str, type[BaseScanner]]:
    """Return the current scanner registry (read-only copy)."""
    return dict(_SCANNER_REGISTRY)


def check_registry() -> dict[str, type[BaseScanner]]:
    """Return the current check registry (read-only copy)."""
    return dict(_CHECK_REGISTRY)


def all_registered() -> dict[str, type[BaseScanner]]:
    """Merged dict of every registered scanner and check."""
    return {**_SCANNER_REGISTRY, **_CHECK_REGISTRY}


# ---------------------------------------------------------------
# Class decorators
# ---------------------------------------------------------------

def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Register *cls* in the global scanner registry under ``cls.name``.

    Usage::

        @register_scanner
        class NiktoScanner(BaseScanner):
            name = "nikto"
            ...
    """
    _SCANNER_REGISTRY[cls.name] = cls
    logger.debug("Registered scanner: %s", cls.name)
    return cls


def register_check(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Register *cls* in the global check registry under ``cls.name``."""
    _CHECK_REGISTRY[cls.name] = cls
    logger.debug("Registered check: %s", cls.name)
    return cls


# ---------------------------------------------------------------
# Method / function decorators
# ---------------------------------------------------------------

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
            return func(self, *args, **kwargs)
        except Exception as exc:
            logger.exception(
                "Scanner %s raised %s: %s", self.name, type(exc).__name__, exc
            )
            return ScannerResult(
                scanner_name=self.name,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

    return wrapper  # type: ignore[return-value]
