from fastapi import Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from ...auth.config import MIN_PASSWORD_LENGTH
from ...auth.cookies import SESSION_COOKIE
from ...auth.middleware import get_auth_service, require_user
from ...auth.models import User
from ...auth.service import AuthService
from ...auth.tokens import hash_token
from ..routing import protected_router
from ..templating import template_context, templates

router = protected_router(prefix="/auth", tags=["auth"])


def _profile_page(
    request: Request, user: User, auth_service: AuthService, **context: str
) -> HTMLResponse:
    sessions = auth_service.list_user_sessions(
        user.user_id, request.cookies.get(SESSION_COOKIE, "")
    )
    return templates.TemplateResponse(
        request,
        "auth/profile.html",
        template_context(request, user=user, sessions=sessions, **context),
    )


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    user: User = Depends(require_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> HTMLResponse:
    return _profile_page(request, user, auth_service)


@router.post("/profile", response_class=HTMLResponse)
async def profile_update(
    request: Request,
    display_name: str = Form(default=""),
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    user: User = Depends(require_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> HTMLResponse:
    updates: dict[str, str] = {}
    error = ""
    success = ""

    if display_name and display_name != user.display_name:
        updates["display_name"] = display_name.strip()

    if new_password:
        if len(new_password) < MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
        elif not user.password_hash or not auth_service.verify_password(
            current_password, user.password_hash
        ):
            error = "Current password is incorrect."
        else:
            updates["password_hash"] = auth_service.hash_password(new_password)

    if not error and updates:
        auth_service.update_user(user.user_id, **updates)
        user = auth_service.get_user_by_id(user.user_id) or user
        success = "Profile updated."
    return _profile_page(request, user, auth_service, error=error, success=success)


@router.delete("/profile/sessions/{token}")
async def revoke_session(
    token: str,
    request: Request,
    user: User = Depends(require_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    """Revoke a specific session (other than the current one)."""
    if token == hash_token(request.cookies.get(SESSION_COOKIE, "")):
        raise HTTPException(status_code=400, detail="Cannot revoke current session")
    if not auth_service.revoke_session_by_hash(user.user_id, token):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=204)
