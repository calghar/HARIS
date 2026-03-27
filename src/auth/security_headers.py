from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

_CSP = (
    "default-src 'self'; "
    "script-src 'self' unpkg.com cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
    "font-src fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

_STATIC_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": _CSP,
}

_HSTS = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security headers on every response.

    When force_https=True, redirects http:// requests to https://
    (intended for production behind a TLS-terminating reverse proxy).
    """

    def __init__(self, app: Any, *, force_https: bool = False) -> None:
        super().__init__(app)
        self._force_https = force_https

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Enforce HTTPS redirect before processing
        if self._force_https and request.url.scheme == "http":
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(https_url), status_code=301)

        response: Response = await call_next(request)

        for header, value in _STATIC_HEADERS.items():
            response.headers[header] = value

        # Only add HSTS over HTTPS (the forwarded scheme after reverse proxy)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = _HSTS

        return response
