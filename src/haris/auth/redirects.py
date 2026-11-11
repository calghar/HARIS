from urllib.parse import quote, urlparse, urlsplit

from fastapi import Request
from fastapi.responses import RedirectResponse

DEFAULT_NEXT = "/"
LOGIN_PATH = "/login"


def safe_next(target: str | None) -> str:
    """Return target only when it is a same-origin relative path, else `/`."""
    if not target or not target.startswith("/") or target.startswith(("//", "/\\")):
        return DEFAULT_NEXT
    # Browsers strip tabs/newlines and treat backslash as slash.
    if any(ord(c) < 0x20 or c in "\\\x7f" for c in target):
        return DEFAULT_NEXT
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return DEFAULT_NEXT
    return target


def redirect_to_next(target: str | None) -> RedirectResponse:
    """303 to a same-origin path; the guard sits at the sink so CodeQL sees it."""
    destination = safe_next(target).replace("\\", "")
    if not urlparse(destination).netloc and not urlparse(destination).scheme:
        return RedirectResponse(destination, status_code=303)
    return RedirectResponse(DEFAULT_NEXT, status_code=303)


def login_url(request: Request) -> str:
    """Login URL that returns the user to the current page."""
    target = DEFAULT_NEXT
    if request.method == "GET":
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
    return f"{LOGIN_PATH}?next={quote(target, safe='/')}"
