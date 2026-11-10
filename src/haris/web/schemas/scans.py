from pydantic import BaseModel, Field


class ScanSummary(BaseModel):
    session_id: str
    target_url: str
    profile_name: str
    started_at: str
    finished_at: str
    risk_posture: str
    finding_count: int
    template_id: str
    scan_state: str
    owner_user_id: str
    scanner_status: dict[str, str]
    errors: list[str]


class ScanList(BaseModel):
    scans: list[ScanSummary]
    page: int
    per_page: int
    total: int
    total_pages: int


class ScanStarted(BaseModel):
    scan_id: str
    status: str
    redirect: str
    notes: list[str] = Field(default_factory=list)


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    started_at: str
    finished_at: str | None
    total_findings: int
    risk_posture: str | None
    scanner_status: dict[str, str]
    llm_enrichment_enabled: bool
    error: str | None


class ScanCancelled(BaseModel):
    scan_id: str
    status: str


class FindingOut(BaseModel):
    finding_id: str
    title: str
    severity: str
    owasp_category: str
    url: str
    scanner: str
    remediation: str
