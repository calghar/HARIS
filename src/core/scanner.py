import abc
import logging
from typing import Any

from ..models import Finding, ScannerResult
from ..models.scan_context import ScanContext
from ..models.target import Target

logger = logging.getLogger(__name__)


class BaseScanner(abc.ABC):
    """Abstract base class that every scanner adapter must implement.

    To add a new scanner:
      1. Subclass BaseScanner.
      2. Implement configure(), scan(), and parse_results().
      3. Register it in src/scanners/__init__.py.
    """

    name: str = "base"
    version: str = "0.0.0"
    description: str = ""

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options: dict[str, Any] = options or {}
        self._configured = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def configure(self, options: dict[str, Any]) -> None:
        """Merge caller-supplied options into scanner defaults.

        Override to validate scanner-specific options.
        """
        self.options.update(options)
        self._configured = True
        logger.debug("%s configured with %s", self.name, self.options)

    @abc.abstractmethod
    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        """Execute the scan against *target* and return results.

        Implementations must respect target.scope (allowed domains,
        excluded paths, rate limits) to stay within authorized boundaries.

        Args:
            target: The target to scan.
            context: Optional cross-scanner intelligence from earlier
                scanners (detected technologies, discovered URLs, etc.).
        """

    @abc.abstractmethod
    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse raw tool output into a list of Finding objects."""

    # ------------------------------------------------------------------
    # Helpers available to subclasses
    # ------------------------------------------------------------------

    def _check_tool_available(self, binary: str) -> bool:
        """Return True if *binary* is found on PATH."""
        import shutil

        return shutil.which(binary) is not None

    def _run_command(
        self,
        cmd: list[str],
        *,
        timeout: int = 600,
        capture: bool = True,
    ) -> tuple[int, str, str]:
        """Run a subprocess and return (returncode, stdout, stderr).

        Raises RuntimeError on timeout.
        """
        import subprocess

        logger.info("Running: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Command timed out after {timeout}s: {' '.join(cmd)}"
            ) from exc

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
