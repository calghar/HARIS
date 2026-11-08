import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request

from .cookies import SEED_COOKIE, SESSION_COOKIE
from .public import PUBLIC_ROUTES

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")


def make_token(secret: str, subject: str) -> str:
    """Derive the CSRF token from the session (or pre-login seed) cookie value."""
    return hmac.new(secret.encode(), subject.encode(), hashlib.sha256).hexdigest()


def _secret(request: Request) -> str:
    return str(request.app.state.haris.settings.secret_key)


def _subject(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE) or request.cookies.get(SEED_COOKIE, "")


def issue_token(request: Request) -> str:
    """Return the page token; a missing seed cookie is queued for the response."""
    subject = _subject(request)
    if not subject:
        subject = secrets.token_urlsafe(32)
        request.state.csrf_seed = subject
    return make_token(_secret(request), subject)


def _is_public(request: Request) -> bool:
    path = getattr(request.scope.get("route"), "path", "")
    return (path, request.method) in PUBLIC_ROUTES


async def _submitted_token(request: Request) -> str:
    header = request.headers.get("X-CSRF-Token", "")
    if header or not any(
        t in request.headers.get("content-type", "") for t in FORM_TYPES
    ):
        return header
    form = await request.form()
    return str(form.get("csrf_token", ""))


async def csrf_protect(request: Request) -> None:
    """App-wide guard: unsafe methods must echo the token bound to the cookie."""
    if request.method in SAFE_METHODS:
        return
    subject = _subject(request)
    if not subject:
        # No ambient cookie: Bearer or anonymous calls reach the auth dependency.
        if _is_public(request):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        return
    submitted = await _submitted_token(request)
    expected = make_token(_secret(request), subject)
    if not secrets.compare_digest(submitted.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
