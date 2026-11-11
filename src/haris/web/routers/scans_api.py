import uuid
from typing import Any

from fastapi import Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from starlette.datastructures import FormData

from ...auth.middleware import get_auth_service, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ...models import ScanState
from ...models.target import check_excluded_paths
from ...scanners.option_policy import prepare_web_scanner_options
from ...verify.settings import VerifyMode
from ..access import Access, require_scan_access, require_template_access, visible_owner
from ..agent_gate import (
    DOCKER_SKIP_NOTE,
    DOCKER_SKIP_REASON,
    docker_blocks_agent,
    remove_agent_run,
    require_agent_allowed,
)
from ..routing import api_router
from ..scan_runtime import (
    FINISHED,
    IN_PROGRESS,
    SCAN_ID_LENGTH,
    ScanJobParams,
    get_scan_record,
    scan_view,
)
from ..schemas.scans import ScanCancelled, ScanList, ScanStarted, ScanStatus
from ..state import AppState, get_state
from ..templating import templates

router = api_router("scans:read", "scans:write", prefix="/scans", tags=["scans"])

DEFAULT_PROFILE = "quick"
DEFAULT_REPORT_FORMATS = ["markdown", "json"]
DEFAULT_RATE_LIMIT = 10.0
DEFAULT_MAX_REQUESTS = 10000
MAX_PER_PAGE = 100


def _number(form: FormData, key: str, default: float) -> float:
    try:
        return float(str(form.get(key, default)))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{key} must be a number") from exc


def _with_template(
    state: AppState, user: User, form: FormData, params: ScanJobParams
) -> ScanJobParams:
    """Fill every field the form left blank from the chosen scan template."""
    require_template_access(state, user, params.template_id)
    tpl = state.store.get_scan_config_template(params.template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    update: dict[str, Any] = {"scanner_options": dict(tpl.scanner_options)}
    if not form.get("profile") or params.profile_name == DEFAULT_PROFILE:
        update["profile_name"] = tpl.profile
    if not form.get("rate_limit"):
        update["rate_limit"] = tpl.rate_limit_rps
    if not form.get("max_requests"):
        update["max_requests"] = tpl.max_requests
    if not params.excluded_paths:
        update["excluded_paths"] = list(tpl.excluded_paths)
    if not params.llm_enrich and tpl.llm_enrichment:
        update["llm_enrich"] = True
        update["llm_backend_name"] = params.llm_backend_name or tpl.llm_backend or None
    return params.model_copy(update=update)


def _checked_params(params: ScanJobParams) -> ScanJobParams:
    try:
        check_excluded_paths(params.excluded_paths)
        options = prepare_web_scanner_options(params.scanner_options)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return params.model_copy(update={"scanner_options": options})


def _verify_mode(form: FormData) -> VerifyMode | None:
    raw = str(form.get("verify", "")).strip()
    if not raw:
        return None
    try:
        return VerifyMode(raw)
    except ValueError as exc:
        modes = ", ".join(m.value for m in VerifyMode)
        raise HTTPException(
            status_code=422, detail=f"verify must be one of: {modes}"
        ) from exc


def _audit(
    auth_service: AuthService,
    request: Request,
    user: User,
    action: AuditAction,
    scan_id: str,
    **details: object,
) -> None:
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=action,
            resource_id=scan_id,
            resource_type="scan",
            details=details,
            ip_address=request.client.host if request.client else "",
        )
    )


@router.post(
    "",
    status_code=202,
    response_model_exclude_defaults=True,
    responses={
        400: {"description": "Bad request or target rejected by the SSRF guard"},
        422: {"description": "Bad verify mode, or llm or agent without what it needs"},
        403: {"description": "Target not authorised, or agent not permitted"},
    },
)
async def start_scan(
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> ScanStarted:
    form = await request.form()
    target_url = str(form.get("target_url", "")).strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    host = state.targets.check_scan_target(user.user_id, target_url)
    params = ScanJobParams(
        target_url=target_url,
        profile_name=str(form.get("profile", DEFAULT_PROFILE)),
        report_formats=[str(f) for f in form.getlist("report_formats")]
        or list(DEFAULT_REPORT_FORMATS),
        excluded_paths=[
            p.strip()
            for p in str(form.get("excluded_paths", "")).split("\n")
            if p.strip()
        ],
        rate_limit=_number(form, "rate_limit", DEFAULT_RATE_LIMIT),
        max_requests=int(_number(form, "max_requests", DEFAULT_MAX_REQUESTS)),
        auth_method=str(form.get("auth_method", "none")),
        llm_enrich=bool(form.get("llm_enrich")),
        llm_backend_name=str(form.get("llm_backend", "")).strip() or None,
        verify=_verify_mode(form),
        agent=bool(form.get("agent")),
        template_id=str(form.get("template_id", "")).strip(),
    )
    if params.template_id:
        params = _with_template(state, user, form, params)
    params = _checked_params(params)
    if params.verify is VerifyMode.LLM and not params.llm_enrich:
        raise HTTPException(
            status_code=422, detail="verify=llm requires LLM enrichment (llm_enrich)"
        )
    note = ""
    if params.agent:
        require_agent_allowed(state, user, host, params.verify)
        if await run_in_threadpool(docker_blocks_agent, params.agent):
            params = params.model_copy(
                update={"agent": False, "agent_skip": DOCKER_SKIP_REASON}
            )
            note = DOCKER_SKIP_NOTE
    scan_id = uuid.uuid4().hex[:SCAN_ID_LENGTH]
    header_value = str(form.get("auth_header_value", ""))
    if params.auth_method != "none" and header_value:
        state.scan_credentials[scan_id] = header_value
    _audit(
        auth_service,
        request,
        user,
        AuditAction.SCAN_STARTED,
        scan_id,
        target_url=target_url,
        profile=params.profile_name,
        agent=params.agent,
    )
    state.jobs.submit(
        scan_id,
        user.user_id,
        params.model_dump(),
        target_url=target_url,
        profile_name=params.profile_name,
        template_id=params.template_id,
        note=note,
    )
    started = ScanStarted(
        scan_id=scan_id, status=ScanState.PENDING.value, redirect=f"/scan/{scan_id}"
    )
    if note:
        return started.model_copy(update={"notes": [note]})
    return started


@router.get("", response_model=None)
async def list_scans(
    page: int = 1,
    per_page: int = 5,
    hostname: str = "",
    severity: str = "",
    date_from: str = "",
    date_to: str = "",
    format: str = "",
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> ScanList | HTMLResponse:
    page = max(page, 1)
    per_page = min(max(per_page, 1), MAX_PER_PAGE)
    rows, total = state.store.list_sessions_paginated(
        page=page,
        per_page=per_page,
        hostname=hostname or None,
        severity=severity or None,
        date_from=date_from or None,
        date_to=date_to or None,
        owner_user_id=visible_owner(state, user),
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
    return ScanList.model_validate(
        {
            "scans": rows,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        }
    )


@router.get(
    "/{scan_id}",
    responses={404: {"description": "Scan not found"}},
)
async def scan_status(
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> ScanStatus:
    record = get_scan_record(state, user, scan_id)
    view = scan_view(state, record)
    finished = ScanState(record["scan_state"]) in FINISHED
    return ScanStatus(
        scan_id=scan_id,
        status=view["status"],
        started_at=view["started_at"],
        finished_at=view["finished_at"],
        total_findings=record["finding_count"],
        risk_posture=record["risk_posture"] if finished else None,
        scanner_status=record["scanner_status"],
        llm_enrichment_enabled=view["llm_enrich"],
        error=view["error"],
    )


@router.post(
    "/{scan_id}/cancel",
    status_code=202,
    responses={
        403: {"description": "Scan is shared read-only"},
        404: {"description": "Scan not found"},
        409: {"description": "Scan is not queued or running"},
    },
)
async def cancel_scan(
    request: Request,
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> ScanCancelled:
    if require_scan_access(state, user, scan_id) is not Access.OWNER:
        raise HTTPException(status_code=403, detail="Only the owner may cancel a scan")
    if not state.jobs.cancel(scan_id):
        get_scan_record(state, user, scan_id)
        raise HTTPException(status_code=409, detail="Scan is not queued or running")
    _audit(auth_service, request, user, AuditAction.SCAN_CANCELLED, scan_id)
    record = get_scan_record(state, user, scan_id)
    return ScanCancelled(scan_id=scan_id, status=record["scan_state"])


@router.delete(
    "/{scan_id}",
    status_code=204,
    responses={
        404: {"description": "Scan not found"},
        403: {"description": "Scan is shared read-only"},
        409: {"description": "Scan is queued or running"},
    },
)
async def delete_scan(
    request: Request,
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    access = require_scan_access(state, user, scan_id)
    if access is not Access.OWNER:
        raise HTTPException(status_code=403, detail="Only the owner may delete a scan")
    record = state.store.get_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if ScanState(record["scan_state"]) in IN_PROGRESS:
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")
    state.store.delete_session(scan_id)
    for report_file in state.settings.reports_dir.glob(f"*_{scan_id}.*"):
        report_file.unlink(missing_ok=True)
    remove_agent_run(state, scan_id)
    _audit(auth_service, request, user, AuditAction.SCAN_DELETED, scan_id)
    return Response(status_code=204)
