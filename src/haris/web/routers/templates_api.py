import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Body, Depends, HTTPException, Request
from pydantic import BaseModel

from ...auth.middleware import get_auth_service, require_admin, require_user
from ...auth.models import AuditAction, AuditEvent, User
from ...auth.service import AuthService
from ...config.loader import load_config
from ...models import ScanConfigTemplate
from ...models.target import check_excluded_paths
from ...models.templates import TemplateMetadata, UpdateResult
from ...scanners.option_policy import ScannerOptionsError, prepare_web_scanner_options
from ...templates.manager import TemplateManager
from ..access import require_template_access, visible_templates
from ..llm_support import reject_legacy_backend
from ..routing import api_router
from ..schemas.sites import TemplateDefault, TemplateDeleted, TemplateSummary
from ..state import AppState, get_state

logger = logging.getLogger(__name__)

router = api_router("scans:read", "scans:write", tags=["templates"])

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
NOT_FOUND = "Template not found"


def _clean_template_fields(body: dict[str, Any]) -> dict[str, Any]:
    fields = {key: body[key] for key in TEMPLATE_FIELDS if key in body}
    reject_legacy_backend(str(fields.get("llm_backend") or ""))
    if "scanner_options" in fields:
        fields["scanner_options"] = _scanner_options(fields["scanner_options"])
    if "excluded_paths" in fields:
        _excluded_paths(fields["excluded_paths"])
    return fields


def _scanner_options(options: object) -> dict[str, dict[str, Any]]:
    try:
        return prepare_web_scanner_options(options)
    except ScannerOptionsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _excluded_paths(patterns: object) -> None:
    try:
        check_excluded_paths(patterns)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class TemplateUpdateRequest(BaseModel):
    scanner: str | None = None
    source_name: str | None = None
    force: bool = False


@router.get("/templates/status")
async def template_status() -> list[TemplateMetadata]:
    try:
        config = load_config()
        mgr = TemplateManager(
            base_dir=config.template_dir, sources=config.template_sources
        )
        return mgr.list_sources()
    except Exception as exc:
        logger.warning("Could not load template status: %s", exc)
        return []


@router.post("/templates/update", responses={500: {"description": "Update failed"}})
async def trigger_template_update(
    body: TemplateUpdateRequest | None = Body(default=None),
    _admin: User = Depends(require_admin),
) -> list[UpdateResult]:
    body = body or TemplateUpdateRequest()
    try:
        config = load_config()
        sources = config.template_sources
        if body.source_name:
            sources = [s for s in sources if s.name == body.source_name]
        mgr = TemplateManager(base_dir=config.template_dir, sources=sources)
        return await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: mgr.update_templates(scanner_name=body.scanner, force=body.force),
        )
    except Exception as exc:
        logger.exception("Template update failed")
        raise HTTPException(status_code=500, detail="Template update failed") from exc


@router.get("/scan-templates")
async def list_scan_templates(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> list[TemplateSummary]:
    return [TemplateSummary.model_validate(t) for t in visible_templates(state, user)]


@router.get(
    "/scan-templates/{template_id}", responses={404: {"description": NOT_FOUND}}
)
async def get_scan_template(
    template_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> ScanConfigTemplate:
    require_template_access(state, user, template_id)
    tpl = state.store.get_scan_config_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return tpl


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


@router.post(
    "/scan-templates",
    status_code=201,
    responses={400: {"description": "name is required"}},
)
async def create_scan_template(
    request: Request,
    body: dict[str, Any] = Body(),
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> ScanConfigTemplate:
    if not body.get("name"):
        raise HTTPException(status_code=400, detail="name is required")
    now = datetime.now(UTC).isoformat()
    tpl = ScanConfigTemplate(
        **_clean_template_fields(body),
        created_at=now,
        updated_at=now,
    )
    state.store.save_scan_config_template(tpl, owner_user_id=user.user_id)
    _audit(auth_service, request, user, AuditAction.TEMPLATE_CREATED, tpl.template_id)
    return tpl


@router.put(
    "/scan-templates/{template_id}", responses={404: {"description": NOT_FOUND}}
)
async def update_scan_template(
    template_id: str,
    request: Request,
    body: dict[str, Any] = Body(),
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> ScanConfigTemplate:
    require_template_access(state, user, template_id, write=True)
    existing = state.store.get_scan_config_template(template_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    merged = existing.model_dump()
    merged.update(_clean_template_fields(body))
    merged["updated_at"] = datetime.now(UTC).isoformat()
    updated = ScanConfigTemplate(**merged)
    state.store.save_scan_config_template(updated)
    _audit(auth_service, request, user, AuditAction.TEMPLATE_UPDATED, template_id)
    return updated


@router.delete(
    "/scan-templates/{template_id}", responses={404: {"description": NOT_FOUND}}
)
async def delete_scan_template(
    request: Request,
    template_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
    auth_service: AuthService = Depends(get_auth_service),
) -> TemplateDeleted:
    require_template_access(state, user, template_id, write=True)
    if not state.store.delete_scan_config_template(template_id):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    _audit(auth_service, request, user, AuditAction.TEMPLATE_DELETED, template_id)
    return TemplateDeleted(deleted=template_id)


@router.post(
    "/scan-templates/{template_id}/set-default",
    responses={404: {"description": NOT_FOUND}},
)
async def set_default_template(
    template_id: str,
    _admin: User = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> TemplateDefault:
    if state.store.get_scan_config_template(template_id) is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    state.store.set_default_scan_config_template(template_id)
    return TemplateDefault(default=template_id)
