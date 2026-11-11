import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..models import Suppression, Verification

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "resources"
    / "schema"
    / "report.schema.json"
)


class FindingRecord(BaseModel):
    """One finding as ``Finding.to_dict`` writes it; 0.7 keys are optional."""

    finding_id: str
    title: str
    description: str
    severity: str
    confidence: str
    owasp_category: str = ""
    cwe_id: str = ""
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    evidence: str = ""
    request_example: str = ""
    response_snippet: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    scanner: str = ""
    found_at: str = ""
    tags: list[str] = Field(default_factory=list)
    observation_id: str = ""
    fingerprint: str = ""
    vuln_class: str = ""
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    verification: Verification = Field(default_factory=Verification)
    suppression: Suppression | None = None
    agent_annotation: str = ""


class CorrelatedRecord(FindingRecord):
    sources: list[tuple[str, str]] = Field(default_factory=list)


class RiskRecord(BaseModel):
    level: str
    description: str = ""


class RemediationRecord(BaseModel):
    title: str
    description: str
    effort: str
    impact: str
    finding_count: int
    category: str = ""


class ReportDocument(BaseModel):
    """The JSON report; a 0.6 report validates because 0.7 keys have defaults."""

    meta: dict[str, Any]
    risk_posture: RiskRecord
    summary: dict[str, Any]
    findings: list[FindingRecord]
    remediation: list[RemediationRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    scan_state: str = "pending"
    stage_log: list[str] = Field(default_factory=list)
    scanner_status: dict[str, str] = Field(default_factory=dict)
    correlated: list[CorrelatedRecord] = Field(default_factory=list)


def report_schema() -> dict[str, Any]:
    schema = ReportDocument.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "HARIS JSON report"
    return schema


def schema_text() -> str:
    return json.dumps(report_schema(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    SCHEMA_PATH.write_text(schema_text(), encoding="utf-8")
