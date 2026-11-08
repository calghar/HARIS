from fastapi import Depends, HTTPException
from fastapi.responses import FileResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ...reporting import REPORTER_REGISTRY
from ..routing import api_router
from ..scan_runtime import domain_slug, get_completed_session, get_scan_for_user
from ..schemas.llm import Enrichment
from ..schemas.scans import FindingOut
from ..state import AppState, get_state

router = api_router("scans:read", prefix="/scans/{scan_id}", tags=["scans"])


@router.get(
    "/report.{fmt}",
    response_model=None,
    responses={
        404: {"description": "Scan not found or not complete"},
        400: {"description": "Unknown format"},
    },
)
async def download_report(
    scan_id: str,
    fmt: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> FileResponse:
    session = get_completed_session(state, user, scan_id)
    reporter_cls = REPORTER_REGISTRY.get(fmt)
    if not reporter_cls:
        raise HTTPException(status_code=400, detail=f"Unknown format: {fmt}")
    reporter = reporter_cls()
    filename = f"report_{domain_slug(session.target.base_url)}_{scan_id}"
    filename += reporter.file_extension
    out_path = state.settings.reports_dir / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    reporter.write(session, out_path)
    return FileResponse(
        path=str(out_path), filename=filename, media_type="application/octet-stream"
    )


@router.get("/findings", responses={404: {"description": "Scan not found"}})
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
    owasp: str | None = None,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> list[FindingOut]:
    _, session, _ = get_scan_for_user(state, user, scan_id)
    findings = session.all_findings if session else []
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    if owasp:
        findings = [f for f in findings if owasp in (f.owasp_category or "")]
    return [
        FindingOut(
            finding_id=f.finding_id,
            title=f.title,
            severity=f.severity.value,
            owasp_category=f.owasp_category or "",
            url=f.url,
            scanner=f.scanner,
            remediation=f.remediation or "",
        )
        for f in findings
    ]


@router.get(
    "/enrichment",
    responses={404: {"description": "Scan not found or not complete"}},
)
async def get_enrichment(
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Enrichment:
    """LLM enrichment data of a finished scan."""
    session = get_completed_session(state, user, scan_id)
    enrichments = {fid: e.model_dump() for fid, e in session.llm_enrichments.items()}
    chains = [c.model_dump() for c in session.attack_chains]
    triaged = [t.model_dump() for t in session.triaged_findings]
    return Enrichment(
        enrichments=enrichments,
        attack_chains=chains,
        triaged_findings=triaged,
        has_enrichment=bool(enrichments or chains or triaged),
    )
