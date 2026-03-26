from pydantic import BaseModel, Field

from .enums import Severity


class EnrichmentContext(BaseModel):
    """Context fed to the LLM when enriching findings."""

    target_url: str = ""
    target_technology_stack: list[str] = Field(default_factory=list)
    other_findings: list[str] = Field(default_factory=list)


class EnrichedFinding(BaseModel):
    """A finding enriched with LLM-generated analysis."""

    finding_id: str
    attack_narrative: str = ""
    """Step-by-step description of how an attacker would exploit this."""

    business_impact_assessment: str = ""
    exploitation_complexity: str = ""
    """``low`` | ``medium`` | ``high``"""

    false_positive_likelihood: str = ""
    """``low`` | ``medium`` | ``high``"""

    related_cwes: list[str] = Field(default_factory=list)
    attack_chain_position: str = ""
    """``initial_access`` | ``escalation`` | ``exfiltration`` | ``""``"""

    variant_suggestions: list[str] = Field(default_factory=list)
    """Natural-language suggestions for similar vulns to check."""


class AttackChain(BaseModel):
    """An identified attack chain spanning multiple findings."""

    chain_id: str
    name: str
    description: str
    finding_ids: list[str] = Field(default_factory=list)
    total_impact: str = ""
    likelihood: str = ""


class TriageContext(BaseModel):
    """Business context for LLM-powered triage."""

    industry: str = ""
    data_sensitivity: str = ""
    compliance_frameworks: list[str] = Field(default_factory=list)


class TriagedFinding(BaseModel):
    """A finding with LLM-assessed triage information."""

    finding_id: str
    original_severity: Severity = Severity.INFO
    adjusted_severity: Severity = Severity.INFO
    exploitability_score: int = 5
    """1-10 scale."""

    business_priority: int = 5
    """1-10 scale."""

    triage_rationale: str = ""
    recommended_timeline: str = ""
    """``immediate`` | ``this_sprint`` | ``next_quarter``"""
