"""Scanner result container model."""

from typing import Any

from pydantic import BaseModel, Field

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
