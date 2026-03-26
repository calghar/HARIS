import abc
import json
import logging
import shutil
import subprocess
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

    # Public API

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

    # Helpers available to subclasses

    def _check_tool_available(self, binary: str) -> bool:
        """Return True if *binary* is found on PATH."""
        return shutil.which(binary) is not None

    def _run_command(
        self,
        cmd: list[str],
        *,
        timeout: int = 600,
        capture: bool = True,
    ) -> tuple[int, str, str]:
        """Run a subprocess and return (returncode, stdout, stderr).

        Handles each failure mode with a specific, descriptive error:
        - ``FileNotFoundError``: binary not installed / not on PATH
        - ``subprocess.TimeoutExpired``: exceeded *timeout* seconds
        - ``subprocess.CalledProcessError``: non-zero exit (if check=True)

        Raises RuntimeError on timeout (preserving backward compat).
        """
        logger.info("Running: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError:
            logger.error(
                "%s binary not found — is it installed and on PATH?",
                cmd[0],
            )
            raise RuntimeError(
                f"{cmd[0]} binary not found. Ensure it is installed and on PATH."
            ) from None
        except subprocess.TimeoutExpired as exc:
            logger.warning(
                "%s timed out after %ds",
                self.name,
                timeout,
            )
            raise RuntimeError(
                f"Command timed out after {timeout}s: {' '.join(cmd)}"
            ) from exc

    @staticmethod
    def _safe_json_load(raw: str, *, label: str = "") -> list[dict[str, Any]] | None:
        """Parse JSON, returning *None* on failure instead of raising.

        If *raw* parses to a single object rather than a list it is
        wrapped in a list for uniform downstream handling.

        Args:
            raw: The JSON string to parse.
            label: Optional label for log messages (e.g. scanner name).

        Returns:
            A list of dicts, or ``None`` if parsing fails.
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "%s: malformed JSON at pos %d: %.200s",
                label or "JSON parse",
                exc.pos,
                raw,
            )
            return None
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            logger.warning("%s: unexpected JSON type %s", label, type(data).__name__)
            return None
        return data

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
