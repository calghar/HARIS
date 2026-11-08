import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from ...auth.config import get_oidc_client
from ...auth.cookies import is_https, set_session_cookie
from ...auth.middleware import get_auth_service
from ...auth.models import AuditAction, AuditEvent
from ...auth.service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["auth"])


def _login_error(code: str) -> RedirectResponse:
    return RedirectResponse(f"/login?error={code}", status_code=303)


@router.get("/login")
async def oidc_login(request: Request) -> Response:
    client = get_oidc_client()
    if not client.is_enabled():
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    return await client.authorize_redirect(
        request, str(request.url_for("oidc_callback"))
    )


@router.get("/callback", name="oidc_callback")
async def oidc_callback(
    request: Request, auth_service: AuthService = Depends(get_auth_service)
) -> Response:
    client = get_oidc_client()
    if not client.is_enabled():
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    try:
        userinfo = await client.handle_callback(request)
    except Exception as exc:
        logger.error("OIDC callback error: %s", exc)
        return _login_error("oidc_error")

    sub = str(userinfo.get("sub", ""))
    email = str(userinfo.get("email", ""))
    if not sub or not email:
        return _login_error("oidc_missing_claims")

    user = auth_service.link_or_create_oidc_user(
        sub,
        email,
        client.get_display_name(userinfo),
        email_verified=client.is_email_verified(userinfo),
        role=client.extract_role(userinfo),
    )
    if user is None:
        return _login_error("oidc_denied")

    ip = request.client.host if request.client else ""
    session = auth_service.create_session(
        user.user_id, ip_address=ip, user_agent=request.headers.get("user-agent", "")
    )
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.USER_LOGIN,
            resource_id=user.user_id,
            resource_type="user",
            details={"provider": "oidc"},
            ip_address=ip,
        )
    )
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, session.token, secure=is_https(request))
    return response
