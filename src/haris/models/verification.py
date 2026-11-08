from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from .enums import VerificationMethod, VerificationOracle, VerificationTier

EXCERPT_LIMIT = 8 * 1024

_T = VerificationTier
ALLOWED_TRANSITIONS = {
    (_T.UNVERIFIED, _T.REPLAY_VERIFIED),
    (_T.UNVERIFIED, _T.REFUTED),
    (_T.UNVERIFIED, _T.EXPLOIT_VALIDATED),
    (_T.REPLAY_VERIFIED, _T.EXPLOIT_VALIDATED),
}


class EvidenceExchange(BaseModel):
    """One request/response pair; headers are already redacted."""

    request_id: str = ""
    role: Literal["probe", "control", "baseline", "poc"] = "probe"
    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_excerpt: str = ""
    status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: str = Field(default="", max_length=EXCERPT_LIMIT)
    elapsed_ms: float = 0.0


class LLMAssessment(BaseModel):
    verdict: Literal["confirmed", "likely_fp", "inconclusive"] = "inconclusive"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    cited_spans: list[str] = Field(default_factory=list)
    model: str = ""
    rationale: str = ""
    status: Literal["ok", "abstained", "invalid", "skipped_budget"] = "ok"


class Verification(BaseModel):
    """Verification state of a finding; the tier moves only via `advance`."""

    tier: VerificationTier = VerificationTier.UNVERIFIED
    method: VerificationMethod = VerificationMethod.NONE
    oracle: VerificationOracle = VerificationOracle.NONE
    baseline_ref: str = ""
    evidence: list[EvidenceExchange] = Field(default_factory=list)
    verdict_source: str = "deterministic"
    llm: LLMAssessment | None = None
    timestamp: str = ""

    def advance(self, tier: VerificationTier) -> None:
        """Move to *tier* if the transition is allowed, else raise ValueError."""
        if tier == self.tier:
            return
        if (self.tier, tier) not in ALLOWED_TRANSITIONS:
            raise ValueError(f"tier transition {self.tier} -> {tier} not allowed")
        self.tier = tier
        self.timestamp = datetime.now(UTC).isoformat()


class Suppression(BaseModel):
    source: Literal["ignore_file"] = "ignore_file"
    reason: str
    author: str
    expires: str
