import logging

from fastapi import HTTPException, Request
from pydantic import BaseModel

from .models import User

logger = logging.getLogger(__name__)

API_V1_PREFIX = "/api/v1/"
BEARER_SCHEME = "bearer"
SCOPES_ATTRIBUTE = "token_scopes"


class ApiPrincipal(BaseModel):
    user: User
    scopes: frozenset[str]


def token_scopes(request: Request) -> frozenset[str] | None:
    """Scopes of the Bearer token behind this request; None for cookie sessions."""
    scopes: frozenset[str] | None = getattr(request.state, SCOPES_ATTRIBUTE, None)
    return scopes


def _bearer_credentials(request: Request) -> str | None:
    """Token string of an `Authorization: Bearer` header on /api/v1, else None."""
    scheme, _, credentials = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != BEARER_SCHEME or not request.url.path.startswith(
        API_V1_PREFIX
    ):
        return None
    return credentials.strip()


def has_bearer_credentials(request: Request) -> bool:
    """Bearer calls are exempt from CSRF; bad tokens still fail with 401."""
    return _bearer_credentials(request) is not None


def bearer_principal(request: Request) -> ApiPrincipal | None:
    """Resolve `Authorization: Bearer` on /api/v1 only; invalid tokens raise 401."""
    credentials = _bearer_credentials(request)
    if credentials is None:
        return None
    state = request.app.state.haris
    record = state.tokens.authenticate(credentials)
    user = state.auth.get_user_by_id(record.user_id) if record else None
    if record is None or user is None or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scopes = frozenset(record.scopes)
    setattr(request.state, SCOPES_ATTRIBUTE, scopes)
    return ApiPrincipal(user=user, scopes=scopes)
