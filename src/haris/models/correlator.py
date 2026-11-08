from pydantic import BaseModel, Field

from .finding import Finding


class CorrelatedFinding(BaseModel):
    """A finding confirmed by one or more scanners.

    Attributes:
        canonical: Deep copy of the best member of the fingerprint bucket.
        sources: (scanner_name, observation_id) of every member.
        consensus_score: Cross-scanner score before tier and LLM adjustments.
    """

    canonical: Finding
    sources: list[tuple[str, str]] = Field(default_factory=list)
    consensus_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @property
    def confirmed_by(self) -> int:
        return len({s[0] for s in self.sources})

    @property
    def multi_confirmed(self) -> bool:
        return self.confirmed_by > 1
