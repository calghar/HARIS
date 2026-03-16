"""Remediation step data model."""

from pydantic import BaseModel, Field

from .enums import Effort, Severity


class RemediationStep(BaseModel):
    """A single actionable remediation item."""

    title: str
    description: str
    effort: Effort
    impact: Severity
    finding_ids: list[str] = Field(default_factory=list)
    finding_count: int = 0
    category: str = ""

    @property
    def priority_score(self) -> float:
        """Higher score = fix this first (high impact, low effort)."""
        impact_weight = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 50,
            Severity.MEDIUM: 20,
            Severity.LOW: 5,
            Severity.INFO: 1,
        }
        effort_divisor = {
            Effort.QUICK_WIN: 1,
            Effort.MODERATE: 3,
            Effort.SIGNIFICANT: 10,
        }
        return (
            impact_weight.get(self.impact, 1)
            * self.finding_count
            / effort_divisor.get(self.effort, 5)
        )
