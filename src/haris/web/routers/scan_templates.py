import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ...auth.middleware import get_auth_service, require_admin, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ...config.loader import load_config
from ...core.profiles import PROFILES
from ...models import ScanConfigTemplate
from ...templates.manager import TemplateManager
from ..access import Access, require_template_access, template_access
from ..ownership import TEMPLATE
from ..page_data import template_form_data
from ..routing import protected_router
from ..state import AppState, get_state
from ..templating import template_context, templates

logger = logging.getLogger(__name__)

router = protected_router(tags=["templates"])

TEMPLATE_FIELDS = (
    "name",
    "description",
    "profile",
    "rate_limit_rps",
    "max_requests",
    "excluded_paths",
    "auth_method",
    "report_formats",
    "llm_enrichment",
    "llm_backend",
    "scanner_options",
    "tags",
)


def _visible_templates(state: AppState, user: User) -> list[dict[str, Any]]:
    return [
        t
        for t in state.store.list_scan_config_templates()
        if template_access(state, user, t["template_id"]) is not Access.NONE
    ]


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
            scan_templates=_visible_templates(state, user),
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


@router.get("/api/templates/status")
async def template_status() -> JSONResponse:
    try:
        config = load_config()
        mgr = TemplateManager(
            base_dir=config.template_dir, sources=config.template_sources
        )
        return JSONResponse([m.model_dump() for m in mgr.list_sources()])
    except Exception as exc:
        logger.warning("Could not load template status: %s", exc)
        return JSONResponse([], status_code=200)


@router.post("/api/templates/update")
async def trigger_template_update(
    request: Request,
    _admin: User = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    body = await request.json() if request.headers.get("content-type") else {}
    scanner_name = body.get("scanner")
    source_name = body.get("source_name")
    force = body.get("force", False)
    try:
        config = load_config()
        sources = config.template_sources
        if source_name:
            sources = [s for s in sources if s.name == source_name]
        mgr = TemplateManager(base_dir=config.template_dir, sources=sources)
        results = await asyncio.get_running_loop().run_in_executor(
            state.executor,
            lambda: mgr.update_templates(scanner_name=scanner_name, force=force),
        )
        return JSONResponse([r.model_dump() for r in results], status_code=200)
    except Exception as exc:
        logger.exception("Template update failed")
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/scan-templates")
async def api_list_scan_templates(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> JSONResponse:
    return JSONResponse(_visible_templates(state, user))


@router.get("/api/scan-templates/{template_id}")
async def api_get_scan_template(
    template_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    require_template_access(state, user, template_id)
    tpl = state.store.get_scan_config_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return JSONResponse(tpl.model_dump())


def _audit(
    auth_service: AuthService,
    request: Request,
    user: User,
    action: AuditAction,
    template_id: str,
) -> None:
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=action,
            resource_id=template_id,
            resource_type="template",
            ip_address=request.client.host if request.client else "",
        )
    )


@router.post("/api/scan-templates")
async def api_create_scan_template(
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    body = await request.json()
    if not body.get("name"):
        raise HTTPException(status_code=400, detail="name is required")
    now = datetime.now(UTC).isoformat()
    tpl = ScanConfigTemplate(
        **{k: body[k] for k in TEMPLATE_FIELDS if k in body},
        created_at=now,
        updated_at=now,
    )
    state.store.save_scan_config_template(tpl)
    state.owners.assign(TEMPLATE, tpl.template_id, user.user_id)
    _audit(auth_service, request, user, AuditAction.TEMPLATE_CREATED, tpl.template_id)
    return JSONResponse(tpl.model_dump(), status_code=201)


@router.put("/api/scan-templates/{template_id}")
async def api_update_scan_template(
    template_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    require_template_access(state, user, template_id, write=True)
    existing = state.store.get_scan_config_template(template_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Template not found")
    body = await request.json()
    merged = existing.model_dump()
    merged.update({k: body[k] for k in TEMPLATE_FIELDS if k in body})
    merged["updated_at"] = datetime.now(UTC).isoformat()
    updated = ScanConfigTemplate(**merged)
    state.store.save_scan_config_template(updated)
    _audit(auth_service, request, user, AuditAction.TEMPLATE_UPDATED, template_id)
    return JSONResponse(updated.model_dump())


@router.delete("/api/scan-templates/{template_id}")
async def api_delete_scan_template(
    request: Request,
    template_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    require_template_access(state, user, template_id, write=True)
    if not state.store.delete_scan_config_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    state.owners.remove(TEMPLATE, template_id)
    _audit(auth_service, request, user, AuditAction.TEMPLATE_DELETED, template_id)
    return JSONResponse({"deleted": template_id})


@router.post("/api/scan-templates/{template_id}/set-default")
async def api_set_default_template(
    template_id: str,
    _admin: User = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    if state.store.get_scan_config_template(template_id) is None:
        raise HTTPException(status_code=404, detail="Template not found")
    state.store.set_default_scan_config_template(template_id)
    return JSONResponse({"default": template_id})
