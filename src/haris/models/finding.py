"""Unified vulnerability finding model."""

import uuid
from datetime import UTC, datetime
from typing import Any, Self

from pydantic import BaseModel, Field, model_validator

from .enums import Confidence, Severity, VerificationTier, confidence_from_score
from .verification import Suppression, Verification


class Finding(BaseModel):
    """A single vulnerability or security observation.

    All scanners and custom checks produce Finding objects that feed into
    the unified reporting pipeline.
    """

    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.TENTATIVE
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)

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
    found_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    observation_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    finding_id: str = ""
    vuln_class: str = ""
    fingerprint: str = ""
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    verification: Verification = Field(default_factory=Verification)
    suppression: Suppression | None = None

    @model_validator(mode="after")
    def _derive_defaults(self) -> Self:
        if not self.finding_id:
            self.finding_id = self.observation_id
        fields = self.model_fields_set
        if "confidence_score" in fields and "confidence" not in fields:
            self.confidence = confidence_from_score(self.confidence_score)
        return self

    @property
    def is_active(self) -> bool:
        """False for refuted or suppressed findings (kept, but not counted)."""
        return (
            self.suppression is None
            and self.verification.tier != VerificationTier.REFUTED
        )

    def __hash__(self) -> int:
        return hash((self.scanner, self.title, self.url, self.parameter))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self.scanner == other.scanner
            and self.title == other.title
            and self.url == other.url
            and self.parameter == other.parameter
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (JSON-friendly)."""
        return {
            "finding_id": self.finding_id,
            "observation_id": self.observation_id,
            "fingerprint": self.fingerprint,
            "vuln_class": self.vuln_class,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
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
            "verification": self.verification.model_dump(mode="json"),
            "suppression": (
                self.suppression.model_dump(mode="json") if self.suppression else None
            ),
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
