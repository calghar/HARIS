import logging
import os
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .email import EmailSender, SMTPConfig
from .middleware import (
    check_rate_limit,
    get_auth_service,
    get_current_user,
    require_admin,
    template_context,
    verify_csrf,
)
from .models import AuditAction, AuditEvent, User, UserPublic, UserRole
from .oidc import OIDCClient, OIDCConfig
from .service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

_MIN_PASSWORD_LENGTH = 12

_oidc_client: OIDCClient | None = None


def get_oidc_client() -> OIDCClient:
    global _oidc_client
    if _oidc_client is None:
        config = OIDCConfig(
            enabled=os.environ.get("HARIS_OIDC_ENABLED", "").lower()
            in {"1", "true", "yes"},
            issuer=os.environ.get("HARIS_OIDC_ISSUER", ""),
            client_id=os.environ.get("HARIS_OIDC_CLIENT_ID", ""),
            client_secret=os.environ.get("HARIS_OIDC_CLIENT_SECRET", ""),
        )
        _oidc_client = OIDCClient(config)
    return _oidc_client


def get_allowed_domains() -> list[str]:
    """Return configured allowed email domains. Empty list = allow all."""
    raw = os.environ.get("HARIS_ALLOWED_EMAIL_DOMAINS", "techforpalestine.org")
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def get_email_sender() -> EmailSender:
    config = SMTPConfig(
        enabled=os.environ.get("HARIS_SMTP_ENABLED", "").lower()
        in {"1", "true", "yes"},
        host=os.environ.get("HARIS_SMTP_HOST", "localhost"),
        port=int(os.environ.get("HARIS_SMTP_PORT", "587")),
        username=os.environ.get("HARIS_SMTP_USERNAME", ""),
        password=os.environ.get("HARIS_SMTP_PASSWORD", ""),
        use_tls=os.environ.get("HARIS_SMTP_USE_TLS", "true").lower() != "false",
        from_address=os.environ.get("HARIS_SMTP_FROM", "noreply@techforpalestine.org"),
        from_name=os.environ.get("HARIS_SMTP_FROM_NAME", "HARIS Security Platform"),
    )
    return EmailSender(config)


def _set_session_cookies(
    response: Response,
    session_token: str,
    csrf_token: str,
    *,
    is_https: bool,
) -> None:
    response.set_cookie(
        "haris_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=8 * 3600,
        path="/",
    )
    response.set_cookie(
        "haris_csrf",
        value=csrf_token,
        httponly=False,
        samesite="strict",
        secure=is_https,
        max_age=8 * 3600,
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie("haris_session", path="/")
    response.delete_cookie("haris_csrf", path="/")
    response.delete_cookie("haris_remember", path="/")


def _is_https(request: Request) -> bool:
    return str(request.url.scheme) == "https"


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    next: str = "/",
    error: str = "",
    auth_service: AuthService = Depends(get_auth_service),
) -> HTMLResponse:
    # If already authenticated, redirect away
    token = request.cookies.get("haris_session", "")
    if token and auth_service.get_session(token):
        return RedirectResponse(next or "/", status_code=302)  # type: ignore[return-value]
    # Pre-seed CSRF cookie so the login form can submit successfully
    csrf_token = request.cookies.get("haris_csrf", "") or secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        request,
        "auth/login.html",
        template_context(
            request,
            next=next,
            error=error,
            oidc_enabled=get_oidc_client().is_enabled(),
            csrf_token=csrf_token,
        ),
    )
    if not request.cookies.get("haris_csrf"):
        response.set_cookie(
            "haris_csrf",
            csrf_token,
            httponly=False,
            samesite="strict",
            secure=_is_https(request),
            max_age=3600,
        )
    return response  # type: ignore[return-value]


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    next: str = Form(default="/"),
    email: str = Form(),
    password: str = Form(),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)

    user = auth_service.authenticate(email, password)
    if not user:
        auth_service.log_audit(
            AuditEvent(
                user_email=email.strip().lower(),
                action=AuditAction.USER_LOGIN_FAILED,
                ip_address=ip,
            )
        )
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            template_context(
                request,
                next=next,
                error="Invalid email or password.",
                oidc_enabled=get_oidc_client().is_enabled(),
            ),
            status_code=401,
        )

    session = auth_service.create_session(
        user.user_id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", ""),
    )
    csrf_token = secrets.token_urlsafe(32)
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.USER_LOGIN,
            resource_id=user.user_id,
            resource_type="user",
            ip_address=ip,
        )
    )

    redirect_to = next if next.startswith("/") else "/"
    response = RedirectResponse(redirect_to, status_code=302)
    _set_session_cookies(
        response, session.token, csrf_token, is_https=_is_https(request)
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    _csrf: Annotated[None, Depends(verify_csrf)],
) -> Response:
    token = request.cookies.get("haris_session", "")
    if token:
        session = auth_service.get_session(token)
        if session:
            user = auth_service.get_user_by_id(session.user_id)
            auth_service.delete_session(token)
            if user:
                auth_service.log_audit(
                    AuditEvent(
                        user_id=user.user_id,
                        user_email=user.email,
                        action=AuditAction.USER_LOGOUT,
                        resource_id=user.user_id,
                        resource_type="user",
                        ip_address=(request.client.host if request.client else ""),
                    )
                )
    response = RedirectResponse("/auth/login", status_code=302)
    _clear_session_cookies(response)
    return response


# -- First-run setup -----------------------------------------------------------


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> HTMLResponse:
    if auth_service.has_any_user():
        raise HTTPException(status_code=404, detail="Not found")
    csrf_token = request.cookies.get("haris_csrf", "") or secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        request, "auth/setup.html", template_context(request, csrf_token=csrf_token)
    )
    if not request.cookies.get("haris_csrf"):
        response.set_cookie(
            "haris_csrf",
            csrf_token,
            httponly=False,
            samesite="strict",
            secure=_is_https(request),
            max_age=3600,
        )
    return response  # type: ignore[return-value]


@router.post("/setup", response_class=HTMLResponse)
async def setup_submit(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    display_name: str = Form(default=""),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    if auth_service.has_any_user():
        raise HTTPException(status_code=404, detail="Not found")
    if len(password) < _MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse(
            request,
            "auth/setup.html",
            template_context(
                request,
                error=(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters."),
            ),
            status_code=422,
        )
    user = auth_service.create_user(
        email=email,
        password=password,
        display_name=display_name or "Administrator",
        role=UserRole.ADMIN,
        is_active=True,
    )
    auth_service.log_audit(
        AuditEvent(
            user_email="system",
            action=AuditAction.USER_CREATED,
            resource_id=user.user_id,
            resource_type="user",
            details={"reason": "first_run_setup"},
        )
    )
    return RedirectResponse("/auth/login?next=/", status_code=302)


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    csrf_token = request.cookies.get("haris_csrf", "") or secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        request, "auth/register.html", template_context(request, csrf_token=csrf_token)
    )
    if not request.cookies.get("haris_csrf"):
        response.set_cookie(
            "haris_csrf",
            csrf_token,
            httponly=False,
            samesite="strict",
            secure=_is_https(request),
            max_age=3600,
        )
    return response  # type: ignore[return-value]


@router.post("/register", response_class=HTMLResponse)
async def register_submit(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    display_name: str = Form(default=""),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    email = email.strip().lower()
    allowed_domains = get_allowed_domains()
    if allowed_domains:
        email_domain = email.split("@")[-1] if "@" in email else ""
        if email_domain not in allowed_domains:
            return templates.TemplateResponse(
                request,
                "auth/register.html",
                template_context(
                    request,
                    error=("Registration is restricted to authorised email addresses."),
                    email=email,
                ),
                status_code=403,
            )

    if len(password) < _MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse(
            request,
            "auth/register.html",
            template_context(
                request,
                error=(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters."),
                email=email,
            ),
            status_code=422,
        )

    if auth_service.get_user_by_email(email):
        # Don't reveal whether the email exists
        return templates.TemplateResponse(
            request,
            "auth/register.html",
            template_context(
                request,
                success=(
                    "If your email is eligible, a verification link has been sent."
                ),
            ),
        )

    user = auth_service.create_user(
        email=email,
        password=password,
        display_name=display_name or email.split("@")[0],
        role=UserRole.USER,
        is_active=False,  # Inactive until email verified
    )
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.USER_REGISTERED,
            resource_id=user.user_id,
            resource_type="user",
            ip_address=request.client.host if request.client else "",
        )
    )

    token = auth_service.create_email_verification_token(user.user_id, "registration")
    sender = get_email_sender()
    sender.send_verification_email(user.email, token, _base_url(request))

    return templates.TemplateResponse(
        request,
        "auth/register.html",
        template_context(
            request,
            success=(
                "Registration successful! "
                "Please check your email to verify your account."
            ),
        ),
    )


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email(
    request: Request,
    token: str = "",
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    if not token:
        return templates.TemplateResponse(
            request,
            "auth/verify_email.html",
            template_context(request, error="Invalid or missing verification token."),
        )
    user = auth_service.consume_email_verification_token(token)
    if not user:
        return templates.TemplateResponse(
            request,
            "auth/verify_email.html",
            template_context(
                request,
                error="Verification link is invalid or has expired.",
            ),
            status_code=400,
        )
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.USER_ACTIVATED,
            resource_id=user.user_id,
            resource_type="user",
        )
    )
    return templates.TemplateResponse(
        request,
        "auth/verify_email.html",
        template_context(request, success=True, email=user.email),
    )


@router.post("/resend-verification", response_class=HTMLResponse)
async def resend_verification(
    request: Request,
    email: str = Form(),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> HTMLResponse:
    user = auth_service.get_user_by_email(email)
    # Always show success to avoid email enumeration
    if user and not user.is_active:
        token = auth_service.create_email_verification_token(
            user.user_id, "registration"
        )
        sender = get_email_sender()
        sender.send_verification_email(user.email, token, _base_url(request))
    return templates.TemplateResponse(
        request,
        "auth/login.html",
        template_context(
            request,
            success=(
                "If your account exists and is unverified, a new link has been sent."
            ),
            oidc_enabled=get_oidc_client().is_enabled(),
        ),
    )


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> HTMLResponse:
    sessions = []
    with auth_service._connect() as conn:
        rows = conn.execute(
            "SELECT * FROM user_sessions WHERE user_id = ? ORDER BY last_seen_at DESC",
            (current_user.user_id,),
        ).fetchall()
        sessions = [dict(r) for r in rows]
    return templates.TemplateResponse(
        request,
        "auth/profile.html",
        template_context(request, user=current_user, sessions=sessions),
    )


@router.post("/profile", response_class=HTMLResponse)
async def profile_update(
    request: Request,
    display_name: str = Form(default=""),
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> HTMLResponse:
    updates: dict = {}
    error = ""
    success = ""

    if display_name and display_name != current_user.display_name:
        updates["display_name"] = display_name.strip()

    if new_password:
        if len(new_password) < _MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {_MIN_PASSWORD_LENGTH} characters."
        elif not current_user.password_hash or not auth_service.verify_password(
            current_password, current_user.password_hash
        ):
            error = "Current password is incorrect."
        else:
            updates["password_hash"] = auth_service.hash_password(new_password)

    if not error and updates:
        auth_service.update_user(current_user.user_id, **updates)
        refreshed = auth_service.get_user_by_id(current_user.user_id)
        if refreshed:
            current_user = refreshed
        success = "Profile updated."

    with auth_service._connect() as conn:
        rows = conn.execute(
            "SELECT * FROM user_sessions WHERE user_id = ? ORDER BY last_seen_at DESC",
            (current_user.user_id,),
        ).fetchall()
        sessions = [dict(r) for r in rows]

    return templates.TemplateResponse(
        request,
        "auth/profile.html",
        template_context(
            request,
            user=current_user,
            sessions=sessions,
            error=error,
            success=success,
        ),
    )


@router.delete("/profile/sessions/{token}")
async def revoke_session(
    token: str,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    """Revoke a specific session (other than the current one)."""
    current_token = request.cookies.get("haris_session", "")
    if token == current_token:
        raise HTTPException(status_code=400, detail="Cannot revoke current session")
    # Verify the session belongs to this user
    with auth_service._connect() as conn:
        row = conn.execute(
            "SELECT user_id FROM user_sessions WHERE token = ?", (token,)
        ).fetchone()
    if not row or row["user_id"] != current_user.user_id:
        raise HTTPException(status_code=404, detail="Session not found")
    auth_service.delete_session(token)
    return Response(status_code=204)


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> HTMLResponse:
    users = [UserPublic.from_user(u) for u in auth_service.list_users()]
    return templates.TemplateResponse(
        request,
        "auth/users.html",
        template_context(request, user=current_user, users=users),
    )


@router.post("/users", response_class=HTMLResponse)
async def create_user(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    display_name: str = Form(default=""),
    role: str = Form(default="user"),
    current_user: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    if len(password) < _MIN_PASSWORD_LENGTH:
        users = [UserPublic.from_user(u) for u in auth_service.list_users()]
        return templates.TemplateResponse(
            request,
            "auth/users.html",
            template_context(
                request,
                user=current_user,
                users=users,
                error=(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters."),
            ),
            status_code=422,
        )
    try:
        new_user = auth_service.create_user(
            email=email,
            password=password,
            display_name=display_name,
            role=UserRole(role),
            is_active=True,
        )
    except Exception as exc:
        users = [UserPublic.from_user(u) for u in auth_service.list_users()]
        return templates.TemplateResponse(
            request,
            "auth/users.html",
            template_context(
                request,
                user=current_user,
                users=users,
                error=str(exc),
            ),
            status_code=422,
        )
    auth_service.log_audit(
        AuditEvent(
            user_id=current_user.user_id,
            user_email=current_user.email,
            action=AuditAction.USER_CREATED,
            resource_id=new_user.user_id,
            resource_type="user",
            ip_address=request.client.host if request.client else "",
        )
    )
    return RedirectResponse("/auth/users", status_code=302)


@router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    request: Request,
    role: str = Form(default=""),
    is_active: str = Form(default=""),
    current_user: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    updates: dict = {}
    if role:
        updates["role"] = UserRole(role)
    if is_active:
        updates["is_active"] = is_active.lower() in {"1", "true", "yes"}
    if updates:
        auth_service.update_user(user_id, **updates)
        auth_service.log_audit(
            AuditEvent(
                user_id=current_user.user_id,
                user_email=current_user.email,
                action=AuditAction.USER_UPDATED,
                resource_id=user_id,
                resource_type="user",
                details=updates,
                ip_address=request.client.host if request.client else "",
            )
        )
    return Response(status_code=204)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    _csrf: Annotated[None, Depends(verify_csrf)],
) -> Response:
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    target = auth_service.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    auth_service.delete_user(user_id)
    auth_service.log_audit(
        AuditEvent(
            user_id=current_user.user_id,
            user_email=current_user.email,
            action=AuditAction.USER_DELETED,
            resource_id=user_id,
            resource_type="user",
            details={"deleted_email": target.email},
            ip_address=request.client.host if request.client else "",
        )
    )
    return Response(status_code=204)


@router.get("/audit-log", response_class=HTMLResponse)
async def audit_log_page(
    request: Request,
    limit: int = 100,
    current_user: User = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
) -> HTMLResponse:
    events = auth_service.get_audit_log(limit=limit)
    return templates.TemplateResponse(
        request,
        "auth/audit_log.html",
        template_context(request, user=current_user, events=events),
    )


@router.get("/oidc/login")
async def oidc_login(request: Request) -> Response:
    client = get_oidc_client()
    if not client.is_enabled():
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    redirect_uri = str(request.url_for("oidc_callback"))
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    client = get_oidc_client()
    if not client.is_enabled():
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    try:
        userinfo = await client.handle_callback(request)
    except Exception as exc:
        logger.error("OIDC callback error: %s", exc)
        return RedirectResponse("/auth/login?error=oidc_error", status_code=302)

    sub = userinfo.get("sub", "")
    email = userinfo.get("email", "")
    if not sub or not email:
        return RedirectResponse(
            "/auth/login?error=oidc_missing_claims", status_code=302
        )

    display_name = client.get_display_name(userinfo)
    user = auth_service.link_or_create_oidc_user(sub, email, display_name)

    ip = request.client.host if request.client else ""
    session = auth_service.create_session(
        user.user_id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", ""),
    )
    csrf_token = secrets.token_urlsafe(32)
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.USER_LOGIN,
            resource_id=user.user_id,
            resource_type="user",
            details={"provider": "oidc"},
            ip_address=ip,
        )
    )

    response = RedirectResponse("/", status_code=302)
    _set_session_cookies(
        response, session.token, csrf_token, is_https=_is_https(request)
    )
    return response
