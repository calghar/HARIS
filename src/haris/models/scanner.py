"""Scanner result container model."""

from typing import Any

from pydantic import BaseModel, Field

from .enums import ScannerStatus
from .finding import Finding


class ScannerResult(BaseModel):
    """Container for raw + parsed results from a scanner run."""

    scanner_name: str
    raw_output: str = ""
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    @property
    def status(self) -> str:
        """Errors win; else the status a scanner set in metadata; else completed."""
        if self.errors:
            return ScannerStatus.FAILED
        return str(self.metadata.get("status", ScannerStatus.COMPLETED))

    @property
    def note(self) -> str:
        """Why a scanner is partial or skipped; empty when it has no note."""
        return str(self.metadata.get("note", ""))
