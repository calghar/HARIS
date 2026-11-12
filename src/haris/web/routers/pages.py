import logging
from typing import Any

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from ...auth.middleware import require_admin, require_user
from ...auth.models import User
from ...config.loader import load_config
from ...core.decorators import all_registered
from ...llm.base import get_default_backend_name
from ..access import visible_owner
from ..llm_support import endpoint_display
from ..routing import protected_router
from ..scanner_info import SCANNER_INFO
from ..state import AppState, get_state
from ..templating import template_context, templates

logger = logging.getLogger(__name__)

router = protected_router(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    owner = visible_owner(state, user)
    summary = state.store.dashboard_summary(owner)
    hostnames = sorted({w["hostname"] for w in state.store.list_websites(owner)})
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        template_context(
            request,
            user=user,
            nav_active="dashboard",
            summary=summary,
            scanners=SCANNER_INFO,
            hostnames=hostnames,
        ),
    )


SCANS_PER_PAGE = 5


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(
    request: Request,
    page: int = 1,
    hostname: str = "",
    severity: str = "",
    date_from: str = "",
    date_to: str = "",
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    page = max(page, 1)
    owner = visible_owner(state, user)
    rows, total = state.store.list_sessions_paginated(
        page=page,
        per_page=SCANS_PER_PAGE,
        hostname=hostname or None,
        severity=severity or None,
        date_from=date_from or None,
        date_to=date_to or None,
        owner_user_id=owner,
    )
    filters = {
        "hostname": hostname,
        "severity": severity,
        "date_from": date_from,
        "date_to": date_to,
    }
    pagination = {
        "page": page,
        "total_pages": max(1, (total + SCANS_PER_PAGE - 1) // SCANS_PER_PAGE),
        "per_page": SCANS_PER_PAGE,
        **filters,
    }
    return templates.TemplateResponse(
        request,
        "scans.html",
        template_context(
            request,
            user=user,
            nav_active="scans",
            scans=rows,
            total=total,
            hostnames=sorted({w["hostname"] for w in state.store.list_websites(owner)}),
            filters=filters,
            pagination=pagination,
        ),
    )


def _llm_settings() -> tuple[dict[str, Any], str]:
    try:
        cfg = load_config()
    except Exception as exc:
        logger.warning("Could not load settings for the settings page: %s", exc)
        return {}, "./templates"
    llm = {
        "backend": cfg.llm.backend,
        "model": cfg.llm.model,
        "endpoint": endpoint_display(cfg.llm.api_base),
        "enrichment_enabled": cfg.llm.enrichment_enabled,
        "threshold": cfg.llm.enrich_severity_threshold,
    }
    return llm, cfg.template_dir


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    user: User = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    summary = state.store.dashboard_summary()
    llm_config, template_dir = _llm_settings()
    return templates.TemplateResponse(
        request,
        "settings.html",
        template_context(
            request,
            user=user,
            nav_active="settings",
            scanners=sorted(all_registered().keys()),
            llm_backend=llm_config.get("backend", get_default_backend_name()),
            llm_model=llm_config.get("model", ""),
            llm_endpoint=llm_config.get("endpoint", ""),
            llm_enrichment_enabled=llm_config.get("enrichment_enabled", False),
            enrich_threshold=llm_config.get("threshold", "high"),
            total_scans=summary.get("total_scans", 0),
            total_websites=summary.get("total_websites", 0),
            template_dir=template_dir,
        ),
    )


@router.get("/licenses", response_class=HTMLResponse)
async def licenses_page(
    request: Request, user: User = Depends(require_user)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "licenses.html",
        template_context(request, user=user, nav_active="", scanners=SCANNER_INFO),
    )
