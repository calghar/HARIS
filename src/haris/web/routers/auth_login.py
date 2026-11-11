from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ...auth.config import (
    MIN_PASSWORD_LENGTH,
    emailed_link_base,
    get_allowed_domains,
    get_email_sender,
    get_oidc_client,
    setup_enabled,
    setup_token_matches,
)
from ...auth.cookies import (
    SESSION_COOKIE,
    clear_session_cookies,
    is_https,
    set_session_cookie,
)
from ...auth.middleware import check_rate_limit, get_auth_service
from ...auth.models import AuditAction, AuditEvent, UserRole
from ...auth.redirects import LOGIN_PATH, safe_next
from ...auth.service import AuthService
from ..templating import template_context, templates

router = APIRouter(tags=["auth"])

LOGIN_ERRORS = {
    "oidc_error": "Single sign-on failed. Please try again.",
    "oidc_missing_claims": "Your identity provider did not return an email address.",
    "oidc_denied": "Single sign-on was refused for this account.",
}


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _send_verification(request: Request, email: str, token: str) -> None:
    base = emailed_link_base(request)
    if base is None:
        return
    get_email_sender().send_verification_email(email, token, base)


def _login_page(request: Request, status_code: int = 200, **context: Any) -> Response:
    return templates.TemplateResponse(
        request,
        "auth/login.html",
        template_context(
            request, oidc_enabled=get_oidc_client().is_enabled(), **context
        ),
        status_code=status_code,
    )


def _password_error() -> str:
    return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    next: str = "/",
    error: str = "",
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    token = request.cookies.get(SESSION_COOKIE, "")
    if token and auth_service.get_session(token):
        return RedirectResponse(safe_next(next), status_code=303)
    return _login_page(
        request,
        next=safe_next(next),
        error=LOGIN_ERRORS.get(error, ""),
        first_run=not auth_service.has_any_user(),
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    next: str = Form(default="/"),
    email: str = Form(),
    password: str = Form(),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    ip = _client_ip(request) or "unknown"
    check_rate_limit(auth_service, ip, email)
    user = auth_service.authenticate(email, password)
    if not user:
        auth_service.log_audit(
            AuditEvent(
                user_email=email.strip().lower(),
                action=AuditAction.USER_LOGIN_FAILED,
                ip_address=ip,
            )
        )
        return _login_page(
            request, 401, next=safe_next(next), error="Invalid email or password."
        )
    session = auth_service.create_session(
        user.user_id, ip_address=ip, user_agent=request.headers.get("user-agent", "")
    )
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
    response = RedirectResponse(safe_next(next), status_code=303)
    set_session_cookie(response, session.token, secure=is_https(request))
    return response


@router.post("/auth/logout")
async def logout(
    request: Request, auth_service: AuthService = Depends(get_auth_service)
) -> Response:
    token = request.cookies.get(SESSION_COOKIE, "")
    session = auth_service.get_session(token) if token else None
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
                    ip_address=_client_ip(request),
                )
            )
    response = RedirectResponse(LOGIN_PATH, status_code=303)
    clear_session_cookies(response)
    return response


@router.get("/auth/setup", response_class=HTMLResponse)
async def setup_page(
    request: Request, auth_service: AuthService = Depends(get_auth_service)
) -> Response:
    if not setup_enabled() or auth_service.has_any_user():
        raise HTTPException(status_code=404, detail="Not found")
    return templates.TemplateResponse(
        request, "auth/setup.html", template_context(request)
    )


@router.post("/auth/setup", response_class=HTMLResponse)
async def setup_submit(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    display_name: str = Form(default=""),
    setup_token: str = Form(default=""),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    if not setup_token_matches(setup_token) or auth_service.has_any_user():
        raise HTTPException(status_code=404, detail="Not found")
    if len(password) < MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse(
            request,
            "auth/setup.html",
            template_context(request, error=_password_error()),
            status_code=422,
        )
    user = auth_service.create_initial_admin(
        email=email,
        password=password,
        display_name=display_name or "Administrator",
    )
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    auth_service.log_audit(
        AuditEvent(
            user_email="system",
            action=AuditAction.USER_CREATED,
            resource_id=user.user_id,
            resource_type="user",
            details={"reason": "first_run_setup"},
        )
    )
    return RedirectResponse(f"{LOGIN_PATH}?next=/", status_code=303)


@router.get("/auth/register", response_class=HTMLResponse)
async def register_page(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "auth/register.html", template_context(request)
    )


@router.post("/auth/register", response_class=HTMLResponse)
async def register_submit(
    request: Request,
    email: str = Form(),
    password: str = Form(),
    display_name: str = Form(default=""),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    email = email.strip().lower()
    check_rate_limit(auth_service, _client_ip(request) or "unknown", email)

    def page(status_code: int = 200, **context: Any) -> Response:
        return templates.TemplateResponse(
            request,
            "auth/register.html",
            template_context(request, **context),
            status_code=status_code,
        )

    allowed_domains = get_allowed_domains()
    domain = email.split("@")[-1] if "@" in email else ""
    if allowed_domains and domain not in allowed_domains:
        return page(
            403,
            error="Registration is restricted to authorised email addresses.",
            email=email,
        )
    if len(password) < MIN_PASSWORD_LENGTH:
        return page(422, error=_password_error(), email=email)
    if auth_service.get_user_by_email(email):
        # Same answer as a fresh signup so addresses cannot be enumerated
        return page(
            success="If your email is eligible, a verification link has been sent."
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
            ip_address=_client_ip(request),
        )
    )
    token = auth_service.create_email_verification_token(user.user_id, "registration")
    _send_verification(request, user.email, token)
    return page(
        success=(
            "Registration successful! Please check your email to verify your account."
        )
    )


@router.get("/auth/verify-email", response_class=HTMLResponse)
async def verify_email(
    request: Request,
    token: str = "",
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    def page(status_code: int = 200, **context: Any) -> Response:
        return templates.TemplateResponse(
            request,
            "auth/verify_email.html",
            template_context(request, **context),
            status_code=status_code,
        )

    if not token:
        return page(error="Invalid or missing verification token.")
    user = auth_service.consume_email_verification_token(token)
    if not user:
        return page(400, error="Verification link is invalid or has expired.")
    auth_service.log_audit(
        AuditEvent(
            user_id=user.user_id,
            user_email=user.email,
            action=AuditAction.USER_ACTIVATED,
            resource_id=user.user_id,
            resource_type="user",
        )
    )
    return page(success=True, email=user.email)


@router.post("/auth/resend-verification", response_class=HTMLResponse)
async def resend_verification(
    request: Request,
    email: str = Form(),
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    email = email.strip().lower()
    check_rate_limit(auth_service, _client_ip(request) or "unknown", email)
    user = auth_service.get_user_by_email(email)
    # Always show success to avoid email enumeration
    if user and not user.is_active and not user.disabled_by_admin:
        token = auth_service.create_email_verification_token(
            user.user_id, "registration"
        )
        _send_verification(request, user.email, token)
    return _login_page(
        request,
        success="If your account exists and is unverified, a new link has been sent.",
    )
