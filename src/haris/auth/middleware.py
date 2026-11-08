import logging
import time
from typing import NoReturn

from fastapi import Depends, HTTPException, Request

from .cookies import SESSION_COOKIE
from .models import User, UserRole
from .redirects import login_url
from .service import AuthService

logger = logging.getLogger(__name__)

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60
_login_attempts: dict[str, tuple[int, float]] = {}


def get_auth_service(request: Request) -> AuthService:
    service: AuthService = request.app.state.haris.auth
    return service


def check_rate_limit(ip: str) -> None:
    """Allow at most LOGIN_MAX_ATTEMPTS per LOGIN_WINDOW_SECONDS per IP.

    Raises HTTPException(429) on violation.
    """
    now = time.time()
    count, start = _login_attempts.get(ip, (0, now))
    if now - start > _LOGIN_WINDOW_SECONDS:
        _login_attempts[ip] = (1, now)
        return
    if count >= _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(  # noqa: TRY301
            status_code=429, detail="Too many login attempts. Please wait."
        )
    _login_attempts[ip] = (count + 1, start)


def _raise_auth_error(request: Request) -> NoReturn:
    """Raise 401; HTMX callers also get HX-Redirect to the login page."""
    headers = None
    if request.headers.get("HX-Request") == "true":
        headers = {"HX-Redirect": login_url(request)}
    raise HTTPException(status_code=401, detail="Not authenticated", headers=headers)


def require_user(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Resolve the active user behind the session cookie or raise 401."""
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


def require_admin(user: User = Depends(require_user)) -> User:
    """Require authenticated user with admin role. Raises 403 otherwise."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
