# Authentication & User Management

HARIS uses a session-based authentication system with role-based access control, CSRF protection, and optional OIDC/KeyCloak integration.

---

## Quick Start

The fastest way to get a running instance with auth:

```bash
# 1. Set credentials in .env
HARIS_ADMIN_EMAIL=admin@example.com
HARIS_ADMIN_PASSWORD=changeme123
HARIS_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# 2. Start
docker compose up    # or: make reload
```

On first start, when the user table is empty and both `HARIS_ADMIN_EMAIL` and `HARIS_ADMIN_PASSWORD` are set, startup creates that admin. An anonymous request to `http://localhost:8000` is redirected to `/login`.

`/auth/setup` answers 404 until `HARIS_SETUP_TOKEN` is set, and once a user exists.

| Variable | Default | Effect |
| -------- | ------- | ------ |
| `HARIS_PUBLIC_URL` | unset | When set, the only base for emailed verification links. When unset, the request base URL is used |
| `HARIS_ALLOWED_HOSTS` | unset | Comma-separated hosts. When set, any other Host header is rejected and www redirect is off. When unset, there is no host check |
| `HARIS_COOKIE_SECURE` | `auto` | `true` forces the Secure flag and `false` omits it. Any other value, including `1` and `yes`, follows the request scheme. Session cookie and CSRF seed cookie |
| `HARIS_SETUP_TOKEN` | unset | `/auth/setup` answers 404 until this is set, and once a user exists. The form field `setup_token` is compared with this value |

---

## Roles

| Role | Permissions |
| ---- | ----------- |
| `user` | Start scans, view and delete own scans, use LLM Q&A, manage own templates and profile |
| `admin` | All of the above on any user's scans and templates + user management, settings, view audit log |

---

## Self-Registration

Users can register at `/auth/register`, subject to the comma-separated domain allowlist in `HARIS_ALLOWED_EMAIL_DOMAINS` (default `techforpalestine.org`; set it empty to allow any domain).

Registration creates an **inactive** account. The user receives a verification email with a 24-hour token link. Clicking it activates the account. If SMTP is not configured, the admin activates accounts manually from `/auth/users`.

The error message on registration deliberately does not reveal which domains are allowed (no information disclosure).

---

## Sessions

- Sessions are stored server-side in the `user_sessions` SQLite table.
- A `secrets.token_urlsafe(32)` token is placed in an `httponly`, `SameSite=lax` cookie (`haris_session`). The table stores only its SHA-256 hash.
- TTL: 8 hours.
- Users can view and revoke individual sessions from `/auth/profile`.
- A password change ends that user's other sessions. The session that sent the change stays.
- Admin deactivation ends every session for that user.
- Expired sessions are purged automatically on startup.

---

## CSRF Protection

HARIS derives a CSRF token from the session cookie:

- The token is an HMAC-SHA256 of the `haris_session` cookie value, keyed with `HARIS_SECRET_KEY`. Before login, the `haris_csrf` seed cookie (`httponly`, `SameSite=lax`, 1 hour) takes its place.
- The `<body>` tag injects it for all HTMX requests: `hx-headers='{"X-CSRF-Token": "..."}'`.
- Traditional forms include it as `<input type="hidden" name="csrf_token">`.
- Every POST, PUT and DELETE must send it in the `X-CSRF-Token` header or the form field. The app compares it with `secrets.compare_digest`.
- Requests with a Bearer token on `/api/v1/*` skip the CSRF check.
- HTMX-triggered 401s return an `HX-Redirect` header instead of a full redirect.

---

## Login Rate Limiting

Login, registration and resend-verification share a limit of 5 attempts per 60 seconds, per client IP and per lower-cased email. The counts are rows in `auth_attempt_counters` in the auth database. Past the limit the route returns 429.

---

## Security Headers

The `SecurityHeadersMiddleware` (`src/haris/auth/security_headers.py`) injects on every response:

| Header | Value |
| ------ | ----- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (HTTPS requests only) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | Per-response nonce on `script-src` and `style-src`, `default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'` (see `build_csp`) |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

Set `HARIS_FORCE_HTTPS=true` to redirect all `http://` requests to `https://`.

---

## Admin User Management

Admins access `/auth/users` to:

- Create new users (any role, any domain)
- Activate accounts that are pending email verification
- Toggle active/inactive status. An admin-disabled account stays inactive through the verification email
- Change role (`user` ↔ `admin`)
- Delete users (cannot delete self)

The audit log at `/auth/audit-log` records all user and scan actions with actor, resource, IP, and timestamp.

---

## OIDC / KeyCloak Integration

Enable SSO via an OIDC provider.

**`.env`:**
```
HARIS_OIDC_ENABLED=true
HARIS_OIDC_ISSUER=https://keycloak.example.com/realms/haris
HARIS_OIDC_CLIENT_ID=haris
HARIS_OIDC_CLIENT_SECRET=<your-client-secret>
```

PKCE (`code_challenge_method: S256`) is enabled by default. Account linking is by email (case-insensitive). Creating a user on OIDC login applies `HARIS_ALLOWED_EMAIL_DOMAINS`. The `haris_role` claim is checked first for the value `haris-admin`; if absent, `realm_access.roles` (KeyCloak default) is used as fallback.

The OIDC login button appears on `/login` when OIDC is enabled. Requires `authlib` and `httpx`:

```bash
uv pip install authlib httpx
```

---

## Email Verification & SMTP

```
HARIS_SMTP_ENABLED=true
HARIS_SMTP_HOST=smtp.example.com
HARIS_SMTP_PORT=587
HARIS_SMTP_USE_TLS=true
HARIS_SMTP_FROM=noreply@example.com
HARIS_SMTP_FROM_NAME=HARIS Security Platform
HARIS_SMTP_USERNAME=smtp-user
HARIS_SMTP_PASSWORD=smtp-pass
```

When SMTP is disabled, verification links are logged at `INFO` level — useful for development and admin-only workflows.

---

## Deployment Behind a Reverse Proxy

When running behind nginx or Caddy (Exoscale, DigitalOcean, etc.):

**uvicorn flags** (add to `docker-compose.yaml` or systemd unit):
```
--proxy-headers --forwarded-allow-ips=127.0.0.1
```

This ensures `request.client.host` resolves to the real client IP (for rate limiting) and `request.url.scheme` is `https` (for HSTS, and for the Secure cookie flag when `HARIS_COOKIE_SECURE` is `auto`).

**`.env`:**
```
HARIS_FORCE_HTTPS=true
```

**nginx snippet:**
```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

---

## Route Protection Matrix

| Route pattern | Minimum role |
| ------------- | ------------ |
| `/login`, `/auth/register`, `/auth/setup`, `/auth/verify-email`, `/health` | Public |
| `/auth/oidc/*` | Public |
| All dashboard routes (`/`, `/websites`, `/scans`, `/scan/*`, `/templates`) | `user` |
| `/api/v1/*` (session cookie or Bearer token `haris_pat_...`), including `POST /api/v1/scans` and `/api/v1/llm/*` | `user` |
| `DELETE /api/v1/scans/{id}`, `PUT/DELETE /api/v1/scan-templates/{id}` | Owner or `admin` |
| `POST /api/v1/scan-templates/{id}/set-default`, `POST /api/v1/templates/update` | `admin` |
| `/settings`, `/auth/users`, `/auth/audit-log` | `admin` |

---

## Auth Module Structure

```
src/haris/auth/
├── __init__.py
├── models.py          — User, UserSession, AuditEvent, enums
├── service.py         — AuthService: CRUD, sessions, tokens, audit log
├── middleware.py      — FastAPI deps: require_user, require_admin, login, register and resend rate limits
├── csrf.py            — CSRF token and app-wide guard
├── bearer.py          — Bearer API token resolution (/api/v1 only)
├── security_headers.py — Starlette security headers middleware
├── oidc.py            — OIDCClient with authlib + PKCE
├── email.py           — SMTP email sender (stdlib smtplib)
└── bootstrap.py       — Env-var admin bootstrap (runs once at startup)

src/haris/web/templates/auth/
├── login.html         — Sign-in form + optional OIDC button
├── register.html      — Self-registration (domain-restricted)
├── verify_email.html  — Email verification confirmation
├── setup.html         — First-run setup wizard
├── users.html         — Admin user management (HTMX CRUD)
├── profile.html       — User profile + active session list
└── audit_log.html     — Admin audit log viewer
```
