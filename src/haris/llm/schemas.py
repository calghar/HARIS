from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, Field

from ..models.enrichment import AttackChain, EnrichedFinding, TriagedFinding
from ..models.enums import Severity


def _lower(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


def _whole_number(value: Any) -> Any:
    return round(value) if isinstance(value, float) else value


Level = Annotated[Literal["low", "medium", "high"], BeforeValidator(_lower)]
OptionalLevel = Annotated[Literal["low", "medium", "high", ""], BeforeValidator(_lower)]
Score = Annotated[int, BeforeValidator(_whole_number), Field(ge=1, le=10)]


class EnrichmentOut(BaseModel):
    attack_narrative: str = ""
    business_impact_assessment: str = ""
    exploitation_complexity: OptionalLevel = ""
    false_positive_likelihood: OptionalLevel = ""
    related_cwes: list[str] = Field(default_factory=list)
    attack_chain_position: Annotated[
        Literal["initial_access", "escalation", "exfiltration", "standalone", ""],
        BeforeValidator(_lower),
    ] = ""
    variant_suggestions: list[str] = Field(default_factory=list)

    def to_model(self, finding_id: str) -> EnrichedFinding:
        return EnrichedFinding(finding_id=finding_id, **self.model_dump())


class ChainOut(BaseModel):
    chain_id: str = ""
    name: str = ""
    description: str = ""
    finding_ids: list[str] = Field(min_length=2)
    total_impact: str = ""
    likelihood: OptionalLevel = ""

    def to_model(self, fallback_id: str, known_ids: set[str]) -> AttackChain | None:
        ids = [i for i in self.finding_ids if i in known_ids]
        if len(ids) < 2:
            return None
        fields = self.model_dump() | {"finding_ids": ids}
        fields["chain_id"] = self.chain_id or fallback_id
        return AttackChain(**fields)


class FalsePositiveOut(BaseModel):
    finding_id: str = Field(min_length=1)
    false_positive_likelihood: Level
    rationale: str = ""


class TriageOut(BaseModel):
    finding_id: str = Field(min_length=1)
    exploitability_score: Score = 5
    business_priority: Score = 5
    adjusted_severity: Annotated[str, BeforeValidator(_lower)] = ""
    triage_rationale: str = ""
    recommended_timeline: Annotated[
        Literal["immediate", "this_sprint", "next_quarter", ""],
        BeforeValidator(_lower),
    ] = ""

    def to_model(self, original: Severity) -> TriagedFinding:
        try:
            adjusted = Severity(self.adjusted_severity)
        except ValueError:
            adjusted = original
        return TriagedFinding(
            finding_id=self.finding_id,
            original_severity=original,
            adjusted_severity=adjusted,
            exploitability_score=self.exploitability_score,
            business_priority=self.business_priority,
            triage_rationale=self.triage_rationale,
            recommended_timeline=self.recommended_timeline,
        )


class VariantOut(BaseModel):
    description: str = ""
    rationale: str = ""
    url_pattern: str = ""
