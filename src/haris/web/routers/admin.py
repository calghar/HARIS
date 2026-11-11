from fastapi import Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...auth.config import MIN_PASSWORD_LENGTH
from ...auth.middleware import get_auth_service, require_admin
from ...auth.models import AuditAction, AuditEvent, User, UserPublic, UserRole
from ...auth.service import AuthService
from ..routing import admin_router
from ..templating import template_context, templates

router = admin_router(prefix="/auth", tags=["admin"])

TRUE_VALUES = {"1", "true", "yes"}


def _users_page(
    request: Request,
    admin: User,
    auth_service: AuthService,
    status_code: int = 200,
    **context: str,
) -> HTMLResponse:
    users = [UserPublic.from_user(u) for u in auth_service.list_users()]
    return templates.TemplateResponse(
        request,
        "auth/users.html",
        template_context(request, user=admin, users=users, **context),
        status_code=status_code,
    )


def _audit(
    auth_service: AuthService,
    request: Request,
    admin: User,
    action: AuditAction,
    user_id: str,
    **details: object,
) -> None:
    auth_service.log_audit(
        AuditEvent(
            user_id=admin.user_id,
            user_email=admin.email,
            action=action,
            resource_id=user_id,
            resource_type="user",
            details=details,
            ip_address=request.client.host if request.client else "",
        )
    )


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    admin: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
) -> HTMLResponse:
    return _users_page(request, admin, auth_service)


@router.post("/users", response_class=HTMLResponse)
async def create_user(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    display_name: str = Form(default=""),
    role: str = Form(default="user"),
    admin: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    if len(password) < MIN_PASSWORD_LENGTH:
        error = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        return _users_page(request, admin, auth_service, 422, error=error)
    try:
        new_user = auth_service.create_user(
            email=email,
            password=password,
            display_name=display_name,
            role=UserRole(role),
            is_active=True,
        )
    except Exception as exc:
        return _users_page(request, admin, auth_service, 422, error=str(exc))
    _audit(auth_service, request, admin, AuditAction.USER_CREATED, new_user.user_id)
    return RedirectResponse("/auth/users", status_code=303)


@router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    request: Request,
    role: str = Form(default=""),
    is_active: str = Form(default=""),
    admin: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    updates: dict[str, object] = {}
    if role:
        if role not in {r.value for r in UserRole}:
            raise HTTPException(status_code=422, detail="Unknown role")
        updates["role"] = role
    if is_active:
        active = is_active.lower() in TRUE_VALUES
        updates["is_active"] = active
        updates["disabled_by_admin"] = not active
    if updates:
        auth_service.update_user(user_id, **updates)
        if updates.get("is_active") is False:
            auth_service.delete_all_user_sessions(user_id)
        _audit(
            auth_service, request, admin, AuditAction.USER_UPDATED, user_id, **updates
        )
    return Response(status_code=204)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    admin: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    if user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    target = auth_service.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    auth_service.delete_user(user_id)
    _audit(
        auth_service,
        request,
        admin,
        AuditAction.USER_DELETED,
        user_id,
        deleted_email=target.email,
    )
    return Response(status_code=204)


@router.get("/audit-log", response_class=HTMLResponse)
async def audit_log_page(
    request: Request,
    limit: int = 100,
    admin: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
) -> HTMLResponse:
    events = auth_service.get_audit_log(limit=limit)
    return templates.TemplateResponse(
        request,
        "auth/audit_log.html",
        template_context(request, user=admin, events=events),
    )
