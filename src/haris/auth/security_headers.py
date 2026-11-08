import secrets
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .cookies import set_seed_cookie


def build_csp(nonce: str) -> str:
    """CSP with a per-response nonce; style attributes stay inline-allowed."""
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "style-src-attr 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'"
    )


_STATIC_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

_HSTS = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security headers and the pre-login CSRF seed cookie.

    When force_https=True, redirects http:// requests to https://
    (intended for production behind a TLS-terminating reverse proxy).
    """

    def __init__(self, app: Any, *, force_https: bool = False) -> None:
        super().__init__(app)
        self._force_https = force_https

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if self._force_https and request.url.scheme == "http":
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(https_url), status_code=301)

        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response: Response = await call_next(request)

        for header, value in _STATIC_HEADERS.items():
            response.headers[header] = value
        response.headers["Content-Security-Policy"] = build_csp(nonce)
        seed = getattr(request.state, "csrf_seed", "")
        if seed:
            set_seed_cookie(response, seed, secure=request.url.scheme == "https")
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = _HSTS
        return response
