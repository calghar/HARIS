from typing import Any

from pydantic import BaseModel


class FindingRef(BaseModel):
    finding_id: str
    title: str
    severity: str
    url: str
    session_id: str
    target_url: str


class RecentWebsite(BaseModel):
    hostname: str
    risk_posture: str
    finding_count: int
    last_scanned: str


class DashboardSummary(BaseModel):
    total_websites: int
    total_scans: int
    open_critical_high: int
    latest_scan_time: str
    recent_findings: list[FindingRef]
    recent_websites: list[RecentWebsite]


class Website(BaseModel):
    hostname: str
    scan_count: int
    last_scanned: str
    first_scanned: str
    latest_risk_posture: str
    latest_finding_count: int


class WebsiteScan(BaseModel):
    session_id: str
    target_url: str
    profile_name: str
    started_at: str
    risk_posture: str
    finding_count: int
    template_id: str
    scanners_used: list[str]


class SeverityTrends(BaseModel):
    labels: list[str]
    datasets: dict[str, list[int]]
    latest_severity: dict[str, int]


class TemplateSummary(BaseModel):
    template_id: str
    name: str
    description: str
    profile: str
    rate_limit_rps: float
    max_requests: int
    scanner_options: dict[str, dict[str, Any]]
    tags: list[str]
    is_default: bool
    created_at: str
    updated_at: str
    owner_user_id: str


class TemplateDeleted(BaseModel):
    deleted: str


class TemplateDefault(BaseModel):
    default: str
