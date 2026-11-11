from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth.bearer import API_V1_PREFIX, token_scopes
from ..auth.middleware import require_admin, require_user
from ..auth.models import User
from ..auth.public import PUBLIC_ROUTES

__all__ = [
    "API_PREFIX",
    "PUBLIC_ROUTES",
    "admin_api_router",
    "admin_router",
    "api_router",
    "protected_router",
    "session_api_router",
]

API_PREFIX = API_V1_PREFIX.rstrip("/")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def protected_router(**kwargs: Any) -> APIRouter:
    """Router whose every route needs an authenticated, active user."""
    return APIRouter(dependencies=[Depends(require_user)], **kwargs)


def admin_router(**kwargs: Any) -> APIRouter:
    """Router whose every route needs the admin role."""
    return APIRouter(dependencies=[Depends(require_admin)], **kwargs)


def require_scope(read: str, write: str | None = None) -> Callable[..., None]:
    """Bearer scope check: `read` for safe methods, else `write` (default `read`)."""

    def check(request: Request, _user: User = Depends(require_user)) -> None:
        scopes = token_scopes(request)
        if scopes is None:
            return
        needed = read if request.method in SAFE_METHODS else (write or read)
        if needed not in scopes:
            raise HTTPException(status_code=403, detail=f"Token lacks scope {needed}")

    return check


def require_session_user(request: Request, user: User = Depends(require_user)) -> User:
    """Reject Bearer tokens: a token must not mint or manage tokens."""
    if token_scopes(request) is not None:
        raise HTTPException(status_code=403, detail="Session login required")
    return user


def api_router(
    read: str, write: str | None = None, *, prefix: str = "", **kwargs: Any
) -> APIRouter:
    """JSON router under /api/v1 gated by a token scope for Bearer callers."""
    return APIRouter(
        prefix=API_PREFIX + prefix,
        dependencies=[Depends(require_user), Depends(require_scope(read, write))],
        **kwargs,
    )


def session_api_router(*, prefix: str = "", **kwargs: Any) -> APIRouter:
    """JSON router under /api/v1 open to cookie sessions only."""
    return APIRouter(
        prefix=API_PREFIX + prefix,
        dependencies=[Depends(require_session_user)],
        **kwargs,
    )


def admin_api_router(*, prefix: str = "", **kwargs: Any) -> APIRouter:
    """JSON router under /api/v1 for admins (and tokens with the admin scope)."""
    return APIRouter(
        prefix=API_PREFIX + prefix, dependencies=[Depends(require_admin)], **kwargs
    )
