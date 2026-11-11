import logging
from typing import NoReturn

from fastapi import Depends, HTTPException, Request

from .bearer import ApiPrincipal, bearer_principal, token_scopes
from .cookies import SESSION_COOKIE
from .models import User, UserRole
from .redirects import login_url
from .service import AuthService

logger = logging.getLogger(__name__)

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60


def get_auth_service(request: Request) -> AuthService:
    service: AuthService = request.app.state.haris.auth
    return service


def check_rate_limit(auth: AuthService, ip: str, email: str) -> None:
    """Allow _LOGIN_MAX_ATTEMPTS per window for this IP and this normalised email."""
    account = email.strip().lower()
    allowed = auth.record_attempt(
        f"ip:{ip}",
        limit=_LOGIN_MAX_ATTEMPTS,
        window_seconds=_LOGIN_WINDOW_SECONDS,
    ) and auth.record_attempt(
        f"acct:{account}",
        limit=_LOGIN_MAX_ATTEMPTS,
        window_seconds=_LOGIN_WINDOW_SECONDS,
    )
    if not allowed:
        raise HTTPException(  # noqa: TRY301
            status_code=429, detail="Too many login attempts. Please wait."
        )


def _raise_auth_error(request: Request) -> NoReturn:
    """Raise 401; HTMX callers also get HX-Redirect to the login page."""
    headers = None
    if request.headers.get("HX-Request") == "true":
        headers = {"HX-Redirect": login_url(request)}
    raise HTTPException(status_code=401, detail="Not authenticated", headers=headers)


def require_user(
    request: Request,
    principal: ApiPrincipal | None = Depends(bearer_principal),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Resolve the active user behind a Bearer token (/api/v1) or session cookie."""
    if principal is not None:
        return principal.user
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        _raise_auth_error(request)
    session = auth_service.get_session(token)
    if not session:
        _raise_auth_error(request)
    user = auth_service.get_user_by_id(session.user_id)
    if not user or not user.is_active:
        _raise_auth_error(request)
    auth_service.touch_session(token)
    return user


def require_admin(request: Request, user: User = Depends(require_user)) -> User:
    """Admin role, plus the `admin` scope when a Bearer token is used."""
    scopes = token_scopes(request)
    if user.role != UserRole.ADMIN or (scopes is not None and "admin" not in scopes):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
