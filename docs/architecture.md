# Architecture

## Overview

HARIS follows a pipeline architecture:

```txt
Configuration -> Target -> Scanners (+ ScanContext) -> Findings -> Enrichment -> Reports
```

## Layers

### 1. Configuration (`src/haris/config/`, `src/haris/models/scan_config_template.py`)

The configuration layer loads settings from three sources (in priority order):

1. **Programmatic overrides** (CLI arguments)
2. **Environment variables** (`HARIS_*`)
3. **YAML config file** (`config/*.yaml`)

This ensures sensitive values (credentials, tokens) never need to be committed to files.

**Scan configuration templates** add a fourth source. They are rows in `scan_config_templates`. A template bundles a scan profile with per-scanner option overrides. A scan stores `template_id` on the session. Five built-in templates are seeded on first run: Quick Surface Scan, Pre-Launch Audit, Full OWASP Top 10, Regression Check and Compliance Audit.

### 2. Target model (`src/haris/models/target.py`)

The `Target` dataclass represents the system under test:

- `base_url`: Root URL of the application
- `scope`: Authorised testing boundaries (domains, paths, rate limits)
- `auth`: Optional authentication configuration

`ScanEngine` calls `ScopedClient.preflight` on the target URL before any scanner runs. `ScopedClient` calls `scope.is_url_in_scope()` on each HTTP request it sends.

`external_target_block` vets each external tool's target host again immediately before that tool starts. After the pre-flight, `ScanEngine` also starts an `EgressProxy` (`src/haris/net/egress_proxy.py`) when an external tool is in the scan and puts its URL in `ScanContext.egress_proxy`. The proxy dials the pre-flight address for the target host and vets every other destination. nuclei (`-proxy`), nikto (`-useproxy`) and Wapiti (`--proxy`) connect through it; nmap and sslyze take the vetted address as their target. A tool without its binding does not start, and nuclei skips the template types that ignore a proxy (`unproxied_template_types`).

### 3. Scanner Interface (`src/haris/core/scanner.py`)

`BaseScanner` defines the contract for all scanners:

```python
configure(options) -> None
scan(target) -> ScannerResult
parse_results(raw_output) -> list[Finding]
```

Two categories of scanners exist:

- **External tool adapters** (`src/haris/scanners/`): Wrap CLI tools like Wapiti, SSLyze, Nmap. They shell out to the tool, capture output (JSON/XML), and parse it.
- **Custom checks** (`src/haris/checks/`): Python checks. HTTP goes through `ScopedClient`. TLS checks use the `ssl` module. They do not shell out.

### 4. Finding model (`src/haris/models/finding.py`)

All scanners produce `Finding` objects with a unified schema:

- Identity: title, description, finding_id
- Classification: severity, confidence, OWASP category, CWE ID
- Location: URL, parameter, HTTP method
- Evidence: raw evidence, example request, response snippet
- Remediation: suggested fix, references
- Verification: tier `unverified`, `replay_verified`, `exploit_validated` or `refuted`. See [`verification.md`](verification.md)

### 5. OWASP Mapping (`src/haris/core/owasp.py`)

A lookup table maps vulnerability keywords and CWE IDs to OWASP Top 10 (2025) categories. The engine auto-enriches findings with OWASP categories based on scanner tags.

### 6. ScanContext (`src/haris/models/scan_context.py`)

The `ScanContext` model accumulates cross-scanner intelligence during a scan:

- `detected_technologies`: Technologies found by earlier scanners (e.g. `nginx`, `wordpress`, `php`)
- `discovered_urls`: finding URLs from the recon stage that start with `http`
- `open_ports`: Open ports from Nmap results
- `server_headers`: Response headers captured by header checks

The recon stage writes `ScanContext`. The scan stage reads it. Nuclei derives its tag group from `detected_technologies`.

### 7. Orchestration Engine (`src/haris/core/engine.py`)

`ScanEngine` runs a scan in this order:

1. Recon: built-in checks and nmap, one at a time, in profile order. This stage writes `ScanContext`.
2. Scan: the other scanners, in parallel. They read the context and do not write it.
3. OWASP tags and stable finding identity.
4. Correlation: one finding per fingerprint. The inputs are not mutated.
5. Ignore file, then verification (`off`, `replay` or `llm`). The engine default is `off`. The CLI default is `replay`.
6. Risk and remediation. An empty scanner status, or a status with no completed or partial scanner, gives posture `unknown`. A scanner may report a note with any status; the note appears in every report format except CSV.

`extract_context` runs only in recon. `header_checks`, `misc_checks` and `info_disclosure` copy `Server`, `X-Powered-By` and `X-AspNet-Version`. nmap copies open ports and product or service names. `extract_context` also copies each finding URL that starts with `http`. Nikto's extractor stays idle because Nikto runs in the scan stage. Wapiti has no extractor.

### 8. Reporting (`src/haris/reporting/`)

`BaseReporter.generate` returns the report text. Six formats are registered: `json`, `markdown`, `html`, `sarif`, `csv` and `junit`. JSON lists every finding, including refuted ones. Markdown and HTML put refuted and suppressed findings in an appendix.

### 9. Authentication Layer (`src/haris/auth/`)

All web routes except the public ones are protected by a session-based authentication system:

- **`models.py`** — Pydantic models: `User`, `UserSession`, `AuditEvent`; enums: `UserRole` (`admin`/`user`), `AuthProvider` (`local`/`oidc`), `AuditAction`
- **`service.py`** — `AuthService`: user CRUD, bcrypt password hashing, server-side session management, email verification tokens, audit logging
- **`middleware.py`** — FastAPI dependencies: `require_user`, `require_admin`, rate limits on login, register and resend (5 attempts / 60 s per IP and per email, stored in the auth database)
- **`csrf.py`** — CSRF token derived from the session cookie and the app-wide guard; Bearer calls on `/api/v1/*` are exempt
- **`bearer.py`** — Resolves `Authorization: Bearer haris_pat_...` tokens on `/api/v1/*` only
- **`security_headers.py`** — Starlette middleware injecting CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` on every response
- **`oidc.py`** — `OIDCClient` wrapping authlib with PKCE, auto-discovery via `/.well-known/openid-configuration`, role extraction from configurable claim
- **`email.py`** — `EmailSender` using stdlib `smtplib`; sends verification and password-reset emails; falls back to logging the link when SMTP is disabled
- **`bootstrap.py`** — Creates the first admin account from `HARIS_ADMIN_EMAIL` / `HARIS_ADMIN_PASSWORD` env vars on startup if the `users` table is empty

Sessions use opaque `secrets.token_urlsafe(32)` tokens stored as SHA-256 hashes in the `user_sessions` table and delivered as `httponly` cookies. CSRF tokens are HMACs of the session cookie, sent in the `X-CSRF-Token` request header (injected by HTMX via `hx-headers` on `<body>`) or the `csrf_token` form field.

### 10. Web Dashboard (`src/haris/web/`)

The FastAPI web application serves a multi-page dashboard. Every route except the public login, registration, OIDC and `/health` routes requires login (minimum `user` role). Bearer API tokens (`haris_pat_...`) are accepted only on `/api/v1/*`:

- **Dashboard** (`/`): Paginated scan history with HTMX filters (website, severity), quick actions, and a recently scanned sidebar.
- **Websites** (`/websites`): Per-target overview. Detail pages show a visual timeline of risk posture changes and finding deltas.
- **Scans** (`/scans`): Filterable by website, severity, template, and scanner name.
- **Templates** (`/templates`): Two-tab hub -- *Scan Configurations* (CRUD for saved presets) and *Scanner Templates* (manage external template sources, trigger updates).
- **New Scan** (`/scan/new`): Template selector dropdown auto-fills the form; "Save as Template" persists current settings. Per-scanner advanced options are collapsible.
- **Settings** (`/settings`): Read-only overview of LLM backends, available scanners, and database info. Requires `admin` role.
- **Auth routes** (`/login`, `/auth/*`): Login, logout, self-registration (domain-restricted), email verification, profile & session management, user management (admin), audit log (admin), OIDC login/callback.

Web scans run the verification stage: `verify` (`off`, `replay` or `llm`, the last only with `llm_enrich`) on `POST /api/v1/scans` and the New Scan form overrides the server default `HARIS_WEB_VERIFY_DEFAULT` (default `replay`).

Navigation order: Dashboard | Websites | Scans | Templates | New Scan (CTA button style). The sidebar bottom anchors a user menu with avatar, popup for Profile / Admin Panel / Sign Out.

## Data Flow

```txt
YAML config + env vars + CLI args + scan template (optional)
        |
        v
    Target + Scope
        |
        v
    Recon: checks and nmap, sequential, writes ScanContext
        |
        v
    Scan: other scanners, parallel, read-only context
        |
        v
    OWASP tags, identity, correlation, ignore file
        |
        v
    Verification (off, replay, or llm) then risk and remediation
        |
        v
    Reporter.generate(session)
```

### Database Schema

The baseline schema version in `schema_version` is 6. Yoyo migrations `0002` through `0008` then hash the token columns, rebuild finding identity, add scan owner and state, and add `api_tokens`, `authorized_targets` and `jobs`.

Baseline tables:

- `scans`, including `template_id` and `started_by`. A saved scan keeps its scope when the row is loaded again. `false_positive_assessments` and `executive_priorities` are columns on this table.
- `findings`
- `remediation_steps`
- `llm_enrichments`, `attack_chains`, `triaged_findings`
- `scan_config_templates`
- `scanner_results`
- `users`
- `user_sessions` (session TTL 8 hours, token stored as a SHA-256 hash)
- `remember_tokens` (30-day TTL)
- `audit_log`
- `email_verifications` (24-hour TTL)

Migration `0008` adds `scans.stage_log` and `findings.agent_annotation`.

## Scan Configuration Templates

Reusable presets that bundle a scan profile with per-scanner option overrides. Five built-in templates are seeded on first run.

| Template | Profile | Key Options |
| -------- | ------- | ----------- |
| Quick Surface Scan | `quick` | Built-in checks only |
| Pre-Launch Audit | `pre-launch` | Nmap common ports, Wapiti folder scope, LLM enrichment |
| Full OWASP Top 10 | `full` | Built-in checks plus Nmap, SSLyze, Wapiti, Nikto, Nuclei. ZAP is not included |
| Regression Check | `regression` | Headers + TLS + misc only |
| Compliance Audit | `compliance` | Nmap + TLS + info disclosure, LLM enrichment |

Per-scanner options per template:

- **Nuclei**: `template_dirs`, `tags`, `severity`, `exclude_tags`, `rate_limit`, `timeout`, `phase2_timeout_s` (seconds for phase 2 in total; default 900 from `nuclei.yaml`; at the limit nuclei is killed, findings are kept and the scanner is `partial`)
- **Nikto**: `plugins`, `tuning`, `timeout`
- **Wapiti**: `modules`, `scope`, `max_scan_time`, `max_links`, `timeout`
- **Nmap**: `ports`, `script_categories`, `timeout`
- See `src/haris/models/scan_config_template.py` for the full option set.

Web template saves and web scan starts check `scanner_options`. An unknown key or scanner name returns HTTP 422. Values must be a bool, a bounded number, or a bounded string or list of strings. URL-valued options go through the SSRF vet. Web `extra_args` reject `-fr` and `-followredirects`. The keys `active` and `authorised` are dropped. Web `dns_checks` accepts only `dns_timeout`. The CLI passes scanner options through unchanged.

**API**: `GET/POST /api/v1/scan-templates`, `GET/PUT/DELETE /api/v1/scan-templates/{id}`, `POST /api/v1/scan-templates/{id}/set-default`
**Web UI**: `/templates` → *Scan Configurations* tab — create, edit, clone, delete, set default.

## Scanner Template Management

External scanner template files are stored in `./templates/{scanner}/{source_name}/` and tracked via `templates/metadata.json`. Sources are configured in `config/default_config.yaml` under `template_sources:`.

| Scanner | Source type | How templates are used |
| ------- | ----------- | ---------------------- |
| Nuclei | `git` — clones `nuclei-templates` repo | Template paths passed as `-t` flags |
| Nikto | `local` — `git pull` on existing `/opt/nikto/` | Updates `db_*` files in-place; Nikto reads them automatically |
| Nmap | None — drop `.nse` files in `templates/nmap/custom/` | NSE files passed with `--script` |
| Wapiti | No template support | — |

**CLI**: `haris update-templates [--scanner nuclei] [--force] [--list]`
**Web UI**: `/templates` → *Scanner Templates* tab — per-source status and update trigger.
**API**: `GET /api/v1/templates/status`, `POST /api/v1/templates/update`

The `./templates/` directory and the `nikto-data` Docker volume are both persisted so updates survive container rebuilds.
