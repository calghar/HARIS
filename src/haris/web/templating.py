from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from ..auth.config import MIN_PASSWORD_LENGTH
from ..auth.csrf import issue_token
from ..auth.models import User

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def _security_context(request: Request) -> dict[str, str]:
    return {
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
        "csrf_token": issue_token(request),
    }


templates = Jinja2Templates(
    directory=str(TEMPLATES_DIR), context_processors=[_security_context]
)
templates.env.globals["min_password_length"] = MIN_PASSWORD_LENGTH


def template_context(
    request: Request, user: User | None = None, **kwargs: Any
) -> dict[str, Any]:
    """Standard context for HTML pages; nonce and CSRF token come from processors."""
    return {
        "request": request,
        "current_user": user,
        "user_is_admin": user is not None and user.is_admin,
        **kwargs,
    }
