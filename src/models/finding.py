"""Unified vulnerability finding model."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from .enums import Confidence, Severity


class Finding(BaseModel):
    """A single vulnerability or security observation.

    All scanners and custom checks produce Finding objects that feed into
    the unified reporting pipeline.
    """

    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.TENTATIVE

    # OWASP mapping (set during normalisation)
    owasp_category: str = ""
    cwe_id: str = ""

    # Affected resource
    url: str = ""
    parameter: str = ""
    method: str = "GET"

    # Evidence
    evidence: str = ""
    request_example: str = ""
    response_snippet: str = ""

    # Remediation
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    # Metadata
    scanner: str = ""
    found_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    finding_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12]
    )
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (JSON-friendly)."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "evidence": self.evidence,
            "request_example": self.request_example,
            "response_snippet": self.response_snippet,
            "remediation": self.remediation,
            "references": self.references,
            "scanner": self.scanner,
            "found_at": self.found_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Deserialise from a plain dict."""
        data = dict(data)  # shallow copy
        data.pop("raw_data", None)

        # Backward compatibility: promote owasp_category_2025
        legacy_2025 = data.pop("owasp_category_2025", "")
        if not data.get("owasp_category") and legacy_2025:
            data["owasp_category"] = legacy_2025

        return cls.model_validate(data)
