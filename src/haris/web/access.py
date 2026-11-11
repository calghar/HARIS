from enum import Enum
from typing import Any

from fastapi import HTTPException

from ..auth.models import User
from .state import AppState


class Access(Enum):
    NONE = 0
    READ = 1
    OWNER = 2


def scan_access(state: AppState, user: User, scan_id: str) -> Access:
    owner = state.store.scan_owner(scan_id)
    if user.is_admin or (owner and owner == user.user_id):
        return Access.OWNER
    return Access.READ if state.settings.share_scans_org_wide else Access.NONE


def require_scan_access(state: AppState, user: User, scan_id: str) -> Access:
    """404 for scans the user may not see, so existence is not disclosed."""
    access = scan_access(state, user, scan_id)
    if access is Access.NONE:
        raise HTTPException(status_code=404, detail="Scan not found")
    return access


def visible_owner(state: AppState, user: User) -> str | None:
    """Owner filter for scan queries, or None when every scan is visible."""
    if user.is_admin or state.settings.share_scans_org_wide:
        return None
    return user.user_id


def template_access_for(user: User, owner: str | None) -> Access:
    """Unowned (built-in) templates are readable by all, writable by admins."""
    if user.is_admin or (owner and owner == user.user_id):
        return Access.OWNER
    return Access.READ if not owner else Access.NONE


def template_access(state: AppState, user: User, template_id: str) -> Access:
    return template_access_for(user, state.store.template_owner(template_id))


def require_template_access(
    state: AppState, user: User, template_id: str, *, write: bool = False
) -> None:
    access = template_access(state, user, template_id)
    if access is Access.NONE:
        raise HTTPException(status_code=404, detail="Template not found")
    if write and access is not Access.OWNER:
        raise HTTPException(status_code=403, detail="Admin access required")


def visible_templates(state: AppState, user: User) -> list[dict[str, Any]]:
    return [
        t
        for t in state.store.list_scan_config_templates()
        if template_access_for(user, t["owner_user_id"]) is not Access.NONE
    ]
