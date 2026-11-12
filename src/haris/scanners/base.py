import ipaddress
import logging
from pathlib import Path
from typing import Any, ClassVar, NamedTuple

from ..core.scanner import BaseScanner
from ..models import ScannerResult
from ..models.scan_context import ScanContext
from ..models.target import Target
from .argv_policy import validate_extra_args
from .process import ToolTimeoutError, run_process
from .redaction import redact_argv, redact_obj, redact_text, secrets_from

logger = logging.getLogger(__name__)

TIMEOUT_RETURNCODE = -1
UNBOUND_REASONS = {"egress_proxy": "no egress proxy", "target_ip": "no vetted address"}


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def compact_number(value: float) -> str:
    """Six decimals at most, no trailing zeros, never an exponent."""
    return f"{value:.6f}".rstrip("0").rstrip(".")


class ToolRun(NamedTuple):
    returncode: int
    stderr: str
    raw: str
    timed_out: bool


class ExternalToolScanner(BaseScanner):
    """Base for scanners that shell out: group-kill timeouts, argv policy, redaction."""

    # ScanContext field the tool cannot start without ("" = none).
    binds_to: ClassVar[str] = ""

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self._secrets: tuple[str, ...] = ()
        self._proxy = ""
        self._vetted_ip = ""
        self._rate_rps = 0.0

    def _unbound(
        self, target: Target, context: ScanContext | None
    ) -> ScannerResult | None:
        """Refusal result when the tool's binding is missing, else None."""
        if not self.binds_to:
            return None
        if self.binds_to == "target_ip" and is_ip_literal(target.hostname):
            return None
        if getattr(context, self.binds_to, ""):
            return None
        reason = UNBOUND_REASONS[self.binds_to]
        return ScannerResult(
            scanner_name=self.name, errors=[f"{self.name} was not started: {reason}"]
        )

    def _begin(self, target: Target, context: ScanContext | None = None) -> None:
        self._secrets = secrets_from(target)
        self._proxy = getattr(context, "egress_proxy", "")
        self._vetted_ip = getattr(context, "target_ip", "")
        self._rate_rps = getattr(context, "tool_rate_rps", 0.0)

    def _extra_args(self) -> list[str]:
        return validate_extra_args(self.name, self.options.get("extra_args", []))

    def _redact(self, text: str) -> str:
        return redact_text(text, self._secrets)

    def _redact_data(self, data: dict[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = redact_obj(data, self._secrets)
        return redacted

    def _run_command(
        self,
        cmd: list[str],
        *,
        timeout: float = 600,
        capture: bool = True,  # noqa: ARG002
    ) -> tuple[int, str, str]:
        """Run *cmd*; a timeout raises ``ToolTimeoutError`` with partial output."""
        logger.info("Running: %s", " ".join(redact_argv(cmd, self._secrets)))
        try:
            return run_process(cmd, timeout)
        except FileNotFoundError:
            logger.error("%s binary not found; is it installed and on PATH?", cmd[0])
            raise RuntimeError(
                f"{cmd[0]} binary not found. Ensure it is installed and on PATH."
            ) from None
        except ToolTimeoutError as exc:
            logger.warning("%s timed out after %ds", self.name, timeout)
            raise ToolTimeoutError(
                f"{self.name} timed out after {timeout}s", exc.stdout, exc.stderr
            ) from None

    def _run_to_file(self, cmd: list[str], output_file: Path, timeout: int) -> ToolRun:
        """Run a tool that writes its report to *output_file*; keep partial output."""
        try:
            returncode, _, stderr = self._run_command(cmd, timeout=timeout)
            timed_out = False
        except ToolTimeoutError as exc:
            returncode, stderr, timed_out = TIMEOUT_RETURNCODE, exc.stderr, True
        raw = output_file.read_text() if output_file.exists() else ""
        return ToolRun(returncode, stderr, raw, timed_out)

    def _timeout_error(self, timeout: int) -> str:
        return f"{self.name} timed out after {timeout}s; partial results kept"
