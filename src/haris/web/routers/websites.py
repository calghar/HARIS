from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ..access import visible_owner
from ..routing import protected_router
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
            websites=state.store.list_websites(visible_owner(state, user)),
        ),
    )


@router.get("/website/{hostname}", response_class=HTMLResponse)
async def website_detail(
    request: Request,
    hostname: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    scans = state.store.get_scans_for_hostname(hostname, visible_owner(state, user))
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
