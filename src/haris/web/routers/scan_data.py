from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from ...auth.middleware import get_auth_service, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ...reporting import REPORTER_REGISTRY
from ..access import Access, require_scan_access
from ..ownership import SCAN
from ..routing import protected_router
from ..scan_runtime import ScanStatus, domain_slug, get_scan_for_user
from ..scoped_views import list_scans
from ..state import AppState, get_state
from ..templating import templates

router = protected_router(tags=["scans"])

MAX_PER_PAGE = 100


@router.get(
    "/api/scan/{scan_id}/report/{fmt}",
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
    scan, session, _ = get_scan_for_user(state, user, scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(status_code=404, detail="Scan not found or not complete")
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


@router.get("/api/scans", response_model=None)
async def list_scans_api(
    page: int = 1,
    per_page: int = 5,
    hostname: str = "",
    severity: str = "",
    date_from: str = "",
    date_to: str = "",
    format: str = "",
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse | HTMLResponse:
    page = max(page, 1)
    per_page = min(max(per_page, 1), MAX_PER_PAGE)
    rows, total = list_scans(
        state,
        user,
        page=page,
        per_page=per_page,
        hostname=hostname or None,
        severity=severity or None,
        date_from=date_from or None,
        date_to=date_to or None,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)
    if format == "html":
        pagination = {
            "page": page,
            "total_pages": total_pages,
            "per_page": per_page,
            "hostname": hostname,
            "severity": severity,
            "date_from": date_from,
            "date_to": date_to,
        }
        html = templates.get_template("_scan_rows.html").render(
            scans=rows, pagination=pagination
        )
        return HTMLResponse(html)
    return JSONResponse(
        {
            "scans": rows,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        }
    )


@router.delete(
    "/api/scan/{scan_id}",
    responses={
        404: {"description": "Scan not found"},
        403: {"description": "Scan is shared read-only"},
        409: {"description": "Scan is still running"},
    },
)
async def delete_scan(
    request: Request,
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    access = require_scan_access(state, user, scan_id)
    if access is not Access.OWNER:
        raise HTTPException(status_code=403, detail="Only the owner may delete a scan")
    scan = state.scans.get(scan_id)
    if scan and scan["status"] == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")

    deleted = state.scans.pop(scan_id, None) is not None
    deleted = state.store.delete_session(scan_id) or deleted
    state.owners.remove(SCAN, scan_id)
    for report_file in state.settings.reports_dir.glob(f"*_{scan_id}.*"):
        report_file.unlink(missing_ok=True)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")

    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.SCAN_DELETED,
            resource_id=scan_id,
            resource_type="scan",
            ip_address=request.client.host if request.client else "",
        )
    )
    return JSONResponse({"deleted": scan_id}, status_code=200)


@router.get(
    "/api/scan/{scan_id}/findings",
    responses={404: {"description": "Scan not found"}},
)
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
    owasp: str | None = None,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    _, session, _ = get_scan_for_user(state, user, scan_id)
    findings = session.all_findings if session else []
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    if owasp:
        findings = [f for f in findings if owasp in (f.owasp_category or "")]
    payload: list[dict[str, Any]] = [
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "severity": f.severity.value,
            "owasp_category": f.owasp_category,
            "url": f.url,
            "scanner": f.scanner,
            "remediation": f.remediation,
        }
        for f in findings
    ]
    return JSONResponse(payload)
