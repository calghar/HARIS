import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ...config.loader import load_config
from ...core.profiles import PROFILES
from ...templates.manager import TemplateManager
from ..access import require_template_access, visible_templates
from ..page_data import template_form_data
from ..routing import protected_router
from ..state import AppState, get_state
from ..templating import template_context, templates

logger = logging.getLogger(__name__)

router = protected_router(tags=["templates"])


def _scanner_sources() -> list[dict[str, Any]]:
    """Every configured template source, downloaded or not."""
    try:
        cfg = load_config()
        mgr = TemplateManager(base_dir=cfg.template_dir, sources=cfg.template_sources)
        meta_by_name = {m.source_name: m.model_dump() for m in mgr.list_sources()}
    except Exception as exc:
        logger.warning("Could not load template sources: %s", exc)
        return []
    return [
        meta_by_name.get(
            src.name,
            {
                "source_name": src.name,
                "scanner": src.scanner,
                "template_count": None,
                "last_updated": None,
                "local_path": None,
            },
        )
        for src in cfg.template_sources
    ]


@router.get("/templates", response_class=HTMLResponse)
async def templates_page(
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "templates.html",
        template_context(
            request,
            user=user,
            nav_active="templates",
            scan_templates=visible_templates(state, user),
            scanner_sources=_scanner_sources(),
        ),
    )


@router.get("/templates/new", response_class=HTMLResponse)
async def template_new_form(
    request: Request, user: User = Depends(require_user)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "template_form.html",
        template_context(
            request,
            user=user,
            nav_active="templates",
            profiles=list(PROFILES.values()),
            template=None,
            page_data=template_form_data(None),
        ),
    )


@router.get("/templates/{template_id}/edit", response_class=HTMLResponse)
async def template_edit_form(
    request: Request,
    template_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    require_template_access(state, user, template_id, write=True)
    tpl = state.store.get_scan_config_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return templates.TemplateResponse(
        request,
        "template_form.html",
        template_context(
            request,
            user=user,
            nav_active="templates",
            profiles=list(PROFILES.values()),
            template=tpl.model_dump(),
            page_data=template_form_data(tpl.model_dump()),
        ),
    )
