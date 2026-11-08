from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ..routing import protected_router
from ..scoped_views import (
    dashboard_summary,
    list_websites,
    scans_for_hostname,
    severity_trends,
)
from ..state import AppState, get_state
from ..templating import template_context, templates

router = protected_router(tags=["websites"])


@router.get("/websites", response_class=HTMLResponse)
async def websites_page(
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "websites.html",
        template_context(
            request,
            user=user,
            nav_active="websites",
            websites=list_websites(state, user),
        ),
    )


@router.get("/website/{hostname}", response_class=HTMLResponse)
async def website_detail(
    request: Request,
    hostname: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    scans = scans_for_hostname(state, user, hostname)
    if not scans:
        raise HTTPException(status_code=404, detail="Website not found")
    template_names = {
        t["template_id"]: t["name"] for t in state.store.list_scan_config_templates()
    }
    return templates.TemplateResponse(
        request,
        "website_detail.html",
        template_context(
            request,
            user=user,
            nav_active="websites",
            hostname=hostname,
            scans=scans,
            first_scanned=scans[-1]["started_at"],
            last_scanned=scans[0]["started_at"],
            template_names=template_names,
        ),
    )


@router.get("/api/dashboard/summary")
async def api_dashboard_summary(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> JSONResponse:
    return JSONResponse(dashboard_summary(state, user))


@router.get("/api/websites")
async def api_list_websites(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> JSONResponse:
    return JSONResponse(list_websites(state, user))


@router.get("/api/website/{hostname}/scans")
async def api_website_scans(
    hostname: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    return JSONResponse(scans_for_hostname(state, user, hostname))


@router.get("/api/website/{hostname}/trends")
async def api_website_trends(
    hostname: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    data: dict[str, Any] = severity_trends(state, user, hostname)
    return JSONResponse(data)
