from typing import Any

from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ...core.decorators import all_registered
from ...core.profiles import PROFILES
from ...core.risk import get_business_impact
from ..page_data import profile_descriptions
from ..routing import protected_router
from ..scan_runtime import get_scan_for_user
from ..state import AppState, get_state
from ..templating import template_context, templates

router = protected_router(tags=["scans"])


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
