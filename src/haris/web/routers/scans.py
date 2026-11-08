import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.datastructures import FormData

from ...auth.middleware import get_auth_service, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ...core.decorators import all_registered
from ...core.profiles import PROFILES
from ...core.risk import get_business_impact
from ...models import AuthConfig, Scope, Target
from ..access import require_template_access
from ..ownership import SCAN
from ..page_data import profile_descriptions
from ..routing import protected_router
from ..scan_runtime import ScanStatus, get_scan_for_user, run_scan_blocking
from ..state import AppState, get_state
from ..templating import template_context, templates

router = protected_router(tags=["scans"])

SCAN_ID_LENGTH = 10
DEFAULT_PROFILE = "quick"
DEFAULT_REPORT_FORMATS = ["markdown", "json"]
DEFAULT_RATE_LIMIT = 10.0
DEFAULT_MAX_REQUESTS = 10000
ALLOWED_SCHEMES = {"http", "https"}


@router.get("/scan/new", response_class=HTMLResponse)
async def new_scan_form(
    request: Request,
    rescan: str | None = Query(default=None),
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    prefill: dict[str, Any] = {}
    if rescan:
        try:
            _, session, _ = get_scan_for_user(state, user, rescan)
        except HTTPException:
            session = None
        if session:
            scope = session.target.scope
            prefill = {
                "target_url": session.target.base_url,
                "profile": session.profile_name,
                "rate_limit": scope.rate_limit_rps,
                "max_requests": scope.max_requests,
                "excluded_paths": "\n".join(scope.excluded_paths or []),
                "auth_method": session.target.auth.method,
                "auth_header_value": session.target.auth.header_value or "",
            }
    return templates.TemplateResponse(
        request,
        "scan_new.html",
        template_context(
            request,
            user=user,
            nav_active="new",
            profiles=list(PROFILES.values()),
            available_scanners=sorted(all_registered().keys()),
            scan_templates=state.store.list_scan_config_templates(),
            prefill=prefill,
            page_data={
                "profileDescriptions": profile_descriptions(),
                "prefillAuthMethod": prefill.get("auth_method", "none"),
            },
        ),
    )


@router.get(
    "/scan/{scan_id}",
    response_class=HTMLResponse,
    responses={404: {"description": "Scan not found"}},
)
async def scan_detail(
    request: Request,
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    scan, session, _ = get_scan_for_user(state, user, scan_id)
    business_impacts = (
        {f.finding_id: get_business_impact(f) for f in session.all_findings}
        if session
        else {}
    )
    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        template_context(
            request,
            user=user,
            nav_active="scans",
            scan=scan,
            session=session,
            business_impacts=business_impacts,
        ),
    )


def _validated_target_url(form: FormData) -> str:
    target_url = str(form.get("target_url", "")).strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    parsed = urlparse(target_url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        raise HTTPException(status_code=400, detail="target_url must be http(s)")
    return target_url


def _number(form: FormData, key: str, default: float) -> float:
    try:
        return float(str(form.get(key, default)))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{key} must be a number") from exc


@router.post("/api/scan/start", responses={400: {"description": "Bad request"}})
async def start_scan(
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    form = await request.form()
    target_url = _validated_target_url(form)
    profile_name = str(form.get("profile", DEFAULT_PROFILE))
    report_formats = [str(f) for f in form.getlist("report_formats")] or list(
        DEFAULT_REPORT_FORMATS
    )
    excluded_paths = [
        p.strip() for p in str(form.get("excluded_paths", "")).split("\n") if p.strip()
    ]
    rate_limit = _number(form, "rate_limit", DEFAULT_RATE_LIMIT)
    max_requests = int(_number(form, "max_requests", DEFAULT_MAX_REQUESTS))
    llm_enrich = bool(form.get("llm_enrich"))
    llm_backend_name = str(form.get("llm_backend", "")).strip() or None
    template_id = str(form.get("template_id", "")).strip()

    scanner_options: dict[str, dict[str, Any]] = {}
    if template_id:
        require_template_access(state, user, template_id)
        tpl = state.store.get_scan_config_template(template_id)
        if tpl is None:
            raise HTTPException(status_code=404, detail="Template not found")
        scanner_options = dict(tpl.scanner_options)
        if not profile_name or profile_name == DEFAULT_PROFILE:
            profile_name = tpl.profile
        if not form.get("rate_limit"):
            rate_limit = tpl.rate_limit_rps
        if not form.get("max_requests"):
            max_requests = tpl.max_requests
        if not excluded_paths:
            excluded_paths = list(tpl.excluded_paths)
        if not llm_enrich and tpl.llm_enrichment:
            llm_enrich = True
            llm_backend_name = llm_backend_name or tpl.llm_backend or None

    scan_id = uuid.uuid4().hex[:SCAN_ID_LENGTH]
    state.owners.assign(SCAN, scan_id, user.user_id)
    state.scans[scan_id] = {
        "scan_id": scan_id,
        "target_url": target_url,
        "profile": profile_name,
        "status": ScanStatus.PENDING,
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "session": None,
        "report_formats": list(report_formats),
        "llm_enrich": llm_enrich,
        "template_id": template_id,
        "error": None,
        "started_by": user.user_id,
    }
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.SCAN_STARTED,
            resource_id=scan_id,
            resource_type="scan",
            details={"target_url": target_url, "profile": profile_name},
            ip_address=request.client.host if request.client else "",
        )
    )
    target = Target(
        base_url=target_url,
        scope=Scope(
            excluded_paths=excluded_paths,
            rate_limit_rps=rate_limit,
            max_requests=max_requests,
        ),
        auth=AuthConfig(
            method=str(form.get("auth_method", "none")),
            header_value=str(form.get("auth_header_value", "")),
        ),
    )
    asyncio.get_running_loop().run_in_executor(
        state.executor,
        run_scan_blocking,
        state,
        scan_id,
        target,
        profile_name,
        list(report_formats),
        llm_enrich,
        llm_backend_name,
        template_id,
        scanner_options,
    )
    return JSONResponse(
        {"scan_id": scan_id, "status": "pending", "redirect": f"/scan/{scan_id}"},
        status_code=202,
    )


@router.get(
    "/api/scan/{scan_id}/status",
    responses={404: {"description": "Scan not found"}},
)
async def scan_status(
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    scan, session, _ = get_scan_for_user(state, user, scan_id)
    return JSONResponse(
        {
            "scan_id": scan_id,
            "status": scan["status"],
            "finished_at": scan.get("finished_at"),
            "total_findings": len(session.all_findings) if session else 0,
            "risk_posture": session.risk_posture.value if session else None,
            "llm_enrichment_enabled": scan.get("llm_enrich", False),
            "error": scan.get("error"),
        }
    )
