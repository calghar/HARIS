"""Scan session data model."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .correlator import CorrelatedFinding
from .enrichment import AttackChain, EnrichedFinding, TriagedFinding
from .enums import OwaspCategory, RiskPosture, Severity
from .finding import Finding
from .remediation import RemediationStep
from .scanner import ScannerResult
from .target import Target


class ScanSession(BaseModel):
    """Captures metadata and results for an entire audit run."""

    session_id: str
    target: Target
    started_at: str = ""
    finished_at: str = ""
    profile_name: str = ""
    profile_intro: str = ""
    scanners_used: list[str] = Field(default_factory=list)
    scanner_results: list[ScannerResult] = Field(default_factory=list)
    all_findings: list[Finding] = Field(default_factory=list)
    correlated: list[CorrelatedFinding] = Field(default_factory=list)
    remediation_steps: list[RemediationStep] = Field(default_factory=list)
    risk_posture: RiskPosture = RiskPosture.EXCELLENT
    risk_posture_text: str = ""
    errors: list[str] = Field(default_factory=list)

    # LLM enrichment data (populated when enrichment_enabled is True)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    llm_enrichments: dict[str, EnrichedFinding] = Field(
        default_factory=dict,
    )
    triaged_findings: list[TriagedFinding] = Field(
        default_factory=list,
    )
    false_positive_assessments: list[dict[str, str]] = Field(
        default_factory=list,
    )
    executive_priorities: str = ""

    # Scan configuration template used (empty if none)
    template_id: str = ""

    @property
    def duration_seconds(self) -> float:
        if not self.started_at or not self.finished_at:
            return 0.0
        start = datetime.fromisoformat(self.started_at)
        end = datetime.fromisoformat(self.finished_at)
        return (end - start).total_seconds()

    @property
    def findings_by_severity(
        self,
    ) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.all_findings:
            grouped[f.severity].append(f)
        return grouped

    @property
    def findings_by_owasp(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}

        for cat in OwaspCategory:
            grouped[cat.value] = []
        grouped["Unmapped"] = []

        for f in self.all_findings:
            key = f.owasp_category or "Unmapped"
            grouped.setdefault(key, []).append(f)
        return grouped

    @property
    def multi_confirmed_count(self) -> int:
        """Number of findings confirmed by 2+ scanners."""
        return sum(1 for c in self.correlated if c.multi_confirmed)

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target.base_url,
            "duration_seconds": self.duration_seconds,
            "total_findings": len(self.all_findings),
            "multi_confirmed": self.multi_confirmed_count,
            "risk_posture": self.risk_posture.value,
            "by_severity": {
                s.value: len(fs) for s, fs in self.findings_by_severity.items()
            },
            "scanners_used": self.scanners_used,
            "remediation_steps": len(self.remediation_steps),
            "errors": self.errors,
        }
