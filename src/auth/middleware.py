import logging
import secrets
import time
from pathlib import Path
from typing import Any, NoReturn

from fastapi import Depends, HTTPException, Request

from .models import User, UserRole
from .service import AuthService

logger = logging.getLogger(__name__)

_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService(db_path=Path("data/HARIS.db"))
    return _auth_service


_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60
_login_attempts: dict[str, tuple[int, float]] = {}


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


async def verify_csrf(request: Request) -> None:
    """Double-submit cookie CSRF validation for all mutating requests.

    Skips GET, HEAD, OPTIONS. Validates that the haris_csrf cookie matches
    either the X-CSRF-Token header (HTMX) or the csrf_token form field.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    # Skip CSRF check for OIDC callback (external redirect, no CSRF cookie available)
    if request.url.path.startswith("/auth/oidc/"):
        return
    cookie_token = request.cookies.get("haris_csrf", "")
    header_token = request.headers.get("X-CSRF-Token", "")
    form_token = ""
    content_type = request.headers.get("content-type", "")
    is_form = (
        "application/x-www-form-urlencoded" in content_type
        or "multipart/form-data" in content_type
    )
    if is_form:
        try:
            form = await request.form()
            form_token = str(form.get("csrf_token", ""))
        except Exception:
            pass
    submitted = header_token or form_token
    if not cookie_token or not submitted:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if not secrets.compare_digest(cookie_token.encode(), submitted.encode()):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def get_current_user(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Retrieve the authenticated user from the session cookie.

    Raises HTTPException(401). For HTMX requests, adds HX-Redirect header
    so the client can handle the redirect client-side.
    """
    token = request.cookies.get("haris_session", "")
    if not token:
        _raise_auth_error(request)
    session = auth_service.get_session(token)
    if not session:
        _raise_auth_error(request)
    user = auth_service.get_user_by_id(session.user_id)
    if not user or not user.is_active:
        _raise_auth_error(request)
    auth_service.touch_session(token)
    return user  # type: ignore[return-value]


def get_current_user_optional(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> User | None:
    """Like get_current_user but returns None for unauthenticated requests."""
    token = request.cookies.get("haris_session", "")
    if not token:
        return None
    session = auth_service.get_session(token)
    if not session:
        return None
    user = auth_service.get_user_by_id(session.user_id)
    if not user or not user.is_active:
        return None
    auth_service.touch_session(token)
    return user


def require_admin(
    user: User = Depends(get_current_user),
) -> User:
    """Require authenticated user with admin role. Raises 403 otherwise."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _raise_auth_error(request: Request) -> NoReturn:
    """Raise 401. For HTMX requests, include HX-Redirect
    so the client redirects gracefully."""
    login_url = f"/auth/login?next={request.url.path}"
    if request.headers.get("HX-Request") == "true":
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"HX-Redirect": login_url},
        )
    raise HTTPException(status_code=401, detail="Not authenticated")


def template_context(
    request: Request,
    user: User | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build the standard template context dict for all HTML responses.

    Injects: request, current_user, csrf_token, user_is_admin.
    Additional kwargs are merged in.
    """
    csrf_token = request.cookies.get("haris_csrf", "")
    return {
        "request": request,
        "current_user": user,
        "csrf_token": csrf_token,
        "user_is_admin": user is not None and user.role == UserRole.ADMIN,
        **kwargs,
    }
