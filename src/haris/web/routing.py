from typing import Any

from fastapi import APIRouter, Depends

from ..auth.middleware import require_admin, require_user
from ..auth.public import PUBLIC_ROUTES

__all__ = ["PUBLIC_ROUTES", "admin_router", "protected_router"]


def protected_router(**kwargs: Any) -> APIRouter:
    """Router whose every route needs an authenticated, active user."""
    return APIRouter(dependencies=[Depends(require_user)], **kwargs)


def admin_router(**kwargs: Any) -> APIRouter:
    """Router whose every route needs the admin role."""
    return APIRouter(dependencies=[Depends(require_admin)], **kwargs)
