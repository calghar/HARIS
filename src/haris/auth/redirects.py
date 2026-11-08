from urllib.parse import quote, urlsplit

from fastapi import Request

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


def login_url(request: Request) -> str:
    """Login URL that returns the user to the current page."""
    target = DEFAULT_NEXT
    if request.method == "GET":
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
    return f"{LOGIN_PATH}?next={quote(target, safe='/')}"
