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

On first start, if the `users` table is empty, the admin account is created automatically from the env vars. Visit `http://localhost:8000` — you will be redirected to `/auth/login`.

If no env vars are set, visit `/auth/setup` to create the first admin interactively (only accessible when zero users exist).

---

## Roles

| Role | Permissions |
| ---- | ----------- |
| `user` | Start scans, view results, use LLM Q&A, manage own profile |
| `admin` | All of the above + user management, settings, delete scans/templates, view audit log |

---

## Self-Registration

Users can register at `/auth/register`, subject to the domain allowlist in `config/default_config.yaml`:

```yaml
auth:
  allowed_email_domains:
    - "techforpalestine.org"   # leave empty [] to allow any domain
```

Registration creates an **inactive** account. The user receives a verification email with a 24-hour token link. Clicking it activates the account. If SMTP is not configured, the admin activates accounts manually from `/auth/users`.

The error message on registration deliberately does not reveal which domains are allowed (no information disclosure).

---

## Sessions

- Sessions are stored server-side in the `user_sessions` SQLite table.
- A `secrets.token_urlsafe(32)` token is placed in an `httponly`, `SameSite=lax` cookie (`haris_session`).
- Default TTL: 8 hours (configurable via `auth.session_ttl_hours`).
- Users can view and revoke individual sessions from `/auth/profile`.
- Expired sessions are purged automatically on startup.

---

## CSRF Protection

HARIS uses the **double-submit cookie** pattern:

- A JS-readable `haris_csrf` cookie is set on login (`SameSite=strict`, non-httponly).
- The `<body>` tag injects it for all HTMX requests: `hx-headers='{"X-CSRF-Token": "..."}'`.
- Traditional forms include it as `<input type="hidden" name="csrf_token">`.
- Middleware validates that the cookie and the header/form value match using `secrets.compare_digest`.
- HTMX-triggered 401s return an `HX-Redirect` header instead of a full redirect.

---

## Login Rate Limiting

5 failed login attempts from the same IP within 60 seconds triggers a `429 Too Many Requests`. The counter resets after the window expires.

---

## Security Headers

The `SecurityHeadersMiddleware` (`src/auth/security_headers.py`) injects on every response:

| Header | Value |
| ------ | ----- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (HTTPS requests only) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' unpkg.com cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; img-src 'self' data:` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

Set `deployment.force_https: true` in `config/default_config.yaml` to redirect all `http://` requests to `https://`.

---

## Admin User Management

Admins access `/auth/users` to:

- Create new users (any role, any domain)
- Activate accounts that are pending email verification
- Toggle active/inactive status
- Change role (`user` ↔ `admin`)
- Delete users (cannot delete self)

The audit log at `/auth/audit-log` records all user and scan actions with actor, resource, IP, and timestamp.

---

## OIDC / KeyCloak Integration

Enable SSO via any OIDC 2.0 provider (tested with KeyCloak):

**`config/default_config.yaml`:**
```yaml
auth:
  oidc:
    enabled: true
    issuer: "https://keycloak.example.com/realms/haris"
    client_id: "haris"
    role_claim: "haris_role"        # custom KeyCloak mapper attribute
    admin_role_value: "haris-admin"
```

**`.env`:**
```
HARIS_OIDC_CLIENT_SECRET=<your-client-secret>
```

PKCE (`code_challenge_method: S256`) is enabled by default. Account linking is by email (case-insensitive). The `role_claim` is checked first; if absent, `realm_access.roles` (KeyCloak default) is used as fallback.

The OIDC login button appears on `/auth/login` when OIDC is enabled. Requires `authlib` and `httpx`:

```bash
uv pip install authlib httpx
```

---

## Email Verification & SMTP

```yaml
auth:
  smtp:
    enabled: true
    host: "smtp.example.com"
    port: 587
    use_tls: true
    from_address: "noreply@example.com"
    from_name: "HARIS Security Platform"
```

```
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

This ensures `request.client.host` resolves to the real client IP (for rate limiting) and `request.url.scheme` is `https` (for the `secure` cookie flag and HSTS header).

**`config/default_config.yaml`:**
```yaml
deployment:
  force_https: true
  trusted_proxy_ips: "127.0.0.1"
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
| `/auth/login`, `/auth/register`, `/auth/setup`, `/auth/verify-email` | Public |
| `/auth/oidc/*` | Public |
| All dashboard routes (`/`, `/websites`, `/scans`, `/scan/*`, `/templates`) | `user` |
| `POST /api/scan/start`, LLM routes | `user` |
| `DELETE /api/scan/*`, `POST/PUT/DELETE /api/scan-templates/*` | `admin` |
| `/settings`, `/auth/users`, `/auth/audit-log` | `admin` |

---

## Auth Module Structure

```
src/auth/
├── __init__.py
├── models.py          — User, UserSession, AuditEvent, enums
├── service.py         — AuthService: CRUD, sessions, tokens, audit log
├── middleware.py      — FastAPI deps: get_current_user, require_admin, CSRF, rate limit
├── security_headers.py — Starlette security headers middleware
├── router.py          — All /auth/* HTTP routes
├── oidc.py            — OIDCClient with authlib + PKCE
├── email.py           — SMTP email sender (stdlib smtplib)
└── bootstrap.py       — Env-var admin bootstrap (runs once at startup)

src/web/templates/auth/
├── login.html         — Sign-in form + optional OIDC button
├── register.html      — Self-registration (domain-restricted)
├── verify_email.html  — Email verification confirmation
├── setup.html         — First-run setup wizard
├── users.html         — Admin user management (HTMX CRUD)
├── profile.html       — User profile + active session list
└── audit_log.html     — Admin audit log viewer
```
