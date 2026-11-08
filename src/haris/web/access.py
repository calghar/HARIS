from enum import Enum

from fastapi import HTTPException

from ..auth.models import User
from .ownership import SCAN, TEMPLATE
from .state import AppState


class Access(Enum):
    NONE = 0
    READ = 1
    OWNER = 2


def scan_access(state: AppState, user: User, scan_id: str) -> Access:
    owner = state.owners.owner_of(SCAN, scan_id)
    if user.is_admin or (owner is not None and owner == user.user_id):
        return Access.OWNER
    return Access.READ if state.settings.share_scans_org_wide else Access.NONE


def require_scan_access(state: AppState, user: User, scan_id: str) -> Access:
    """404 for scans the user may not see, so existence is not disclosed."""
    access = scan_access(state, user, scan_id)
    if access is Access.NONE:
        raise HTTPException(status_code=404, detail="Scan not found")
    return access


def visible_scan_ids(state: AppState, user: User) -> set[str] | None:
    """Ids the user may list, or None when every scan is visible."""
    if user.is_admin or state.settings.share_scans_org_wide:
        return None
    return state.owners.owned_by(SCAN, user.user_id)


def template_access(state: AppState, user: User, template_id: str) -> Access:
    """Unowned (built-in) templates are readable by all, writable by admins."""
    owner = state.owners.owner_of(TEMPLATE, template_id)
    if user.is_admin or owner == user.user_id:
        return Access.OWNER
    return Access.READ if owner is None else Access.NONE


def require_template_access(
    state: AppState, user: User, template_id: str, *, write: bool = False
) -> None:
    access = template_access(state, user, template_id)
    if access is Access.NONE:
        raise HTTPException(status_code=404, detail="Template not found")
    if write and access is not Access.OWNER:
        raise HTTPException(status_code=403, detail="Admin access required")
