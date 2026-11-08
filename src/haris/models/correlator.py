from pydantic import BaseModel, Field

from .finding import Finding


class CorrelatedFinding(BaseModel):
    """A finding confirmed by one or more scanners.

    Attributes:
        canonical: The highest-confidence Finding chosen as
            representative.
        sources: List of (scanner_name, finding_id) that
            reported the same issue.
    """

    canonical: Finding
    sources: list[tuple[str, str]] = Field(default_factory=list)

    @property
    def confirmed_by(self) -> int:
        return len({s[0] for s in self.sources})

    @property
    def multi_confirmed(self) -> bool:
        return self.confirmed_by > 1
