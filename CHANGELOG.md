# Changelog
<!--markdownlint-disable MD024-->
## 0.6.1 — 2026-03-28

### Fixed

- Removed `disallow_untyped_defs = true` from mypy config — overly strict for an open-source project
- Fixed `warn_return_any` error in `src/auth/router.py` (`_is_https` returning `Any`)
- Fixed invalid `base_url` keyword argument passed to `Scope()` in `test_nuclei_scanner.py`
- CI mypy job now checks `tests/` in addition to `src/`
- Cleaned up redundant type annotations across test files

## 0.6.0 — 2026-03-27

### Added

- **Authentication system** — local email/password registration with bcrypt hashing, session management, and OIDC (OpenID Connect) provider support for SSO
- `src/auth/` module with `AuthService`, `OIDCClient`, email sender, security headers middleware, and auth router
- Database schema V6 — `users`, `user_sessions`, `remember_tokens`, `email_verification_tokens`, `audit_log` tables
- Login, registration, and account management pages in the web dashboard
- Admin bootstrapping from `HARIS_ADMIN_EMAIL` / `HARIS_ADMIN_PASSWORD` environment variables
- Audit logging for authentication events (login, logout, registration, password changes)
- Security headers middleware (CSP, HSTS, X-Content-Type-Options, X-Frame-Options)
- `Makefile` for common development tasks

### Changed

- Web dashboard requires authentication — all scan and report routes are now protected
- `base.html` template updated with user menu, auth navigation, and theme toggle
- Extracted shared JavaScript into `main.js` and `theme-init.js`
- Updated `style.css` with auth form styles and layout improvements
- Added `bcrypt` and `authlib` (optional, for OIDC) to project dependencies

### Fixed

- Removed dead code in `cookie_checks.py` and `misc_checks.py`
- Cleaned up unused imports in `context.py` and `adapters.py`

## 0.5.1 — 2026-03-26

### Changed

- **Split scanner config into per-scanner YAML files** — each scanner now loads config from `config/scanners/{scanner_name}.yaml` instead of hardcoded Python dicts
- Created `config/scanners/nikto.yaml` (severity_map, keyword_rules, osvdb_critical)
- Created `config/scanners/nmap.yaml` (risky_services, default_ports, default_extra_args)
- Created `config/scanners/sslyze.yaml` (deprecated_protocols, vulnerability_checks)
- Created `config/scanners/wapiti.yaml` (severity_map, category_tags)
- Created `config/scanners/nuclei.yaml` — moved all nuclei config out of `scanner_data.yaml`
- `config/scanner_data.yaml` trimmed to cross-scanner shared data only (nikto tech_keywords)
- Replaced `ScannerDataLoader` class with generic `_load_scanner_config()` and per-scanner getters in `src/data/scanner_config.py`
- Updated `nikto_scanner.py`, `nmap_scanner.py`, `sslyze_scanner.py`, `wapiti_scanner.py` to load config from YAML via lazy-initialised accessors
- Updated `src/data/__init__.py` exports to include new per-scanner getters

## 0.5.0 — 2026-03-26

### Added

- **Cross-scanner intelligence** (`ScanContext` model) — scanners share detected technologies, discovered URLs, open ports, and server headers so downstream scanners make smarter decisions
- **Multi-phase Nuclei scanning** — Phase 1 (technology fingerprinting), Phase 2a (broad vulnerability scan across 8 template directories), Phase 2b (tech-targeted scan with tags/workflows, conditional)
- `ScanContext` Pydantic model (`src/models/scan_context.py`) with `add_technologies()` and `add_urls()` for case-insensitive deduplication
- `ScanEngine` context accumulation: extracts technologies from Nmap, Nikto, header_checks, and Wapiti between scanner runs
- `http/cves` directory (3 830 templates) added to Nuclei `DEFAULT_TEMPLATE_DIRS` — the largest and most impactful template category was previously missing
- Technology-to-tag/workflow mapping tables (`TECH_TAG_MAP`, `TECH_WORKFLOW_MAP`) covering 40+ technologies with Nuclei-specific tags and 15 official workflows
- `_NUCLEI_META_TAGS` filter (18 generic Nuclei metadata tags) to prevent false technology extraction
- Technology extraction from Nuclei `extracted-results` field (e.g. metatag-cms "Astro v5.15.9" → `astro`)
- 70+ new tests across `test_nuclei_scanner.py` (56), `test_engine.py` (20), `test_scan_context.py` (14)

### Fixed

- Nuclei Phase 2 returning 0 findings — `-tags` combined with `-t` template dirs created an AND-filter excluding nearly all templates; split into Phase 2a (broad, no tags) and Phase 2b (tech-targeted, conditional)
- Nuclei `_extract_technologies()` capturing generic metadata tags (waf, misc, discovery, cms, tech) as real technologies — now filtered via `_NUCLEI_META_TAGS` frozenset
- Nuclei `extracted-results` field not stored in `raw_data`, causing metatag-cms technology names to be lost
- Wapiti URL extraction including non-HTTP URLs (e.g. `mailto:`, `javascript:`) in `ScanContext`
- `ScanEngine._extract_context()` Nikto technology keyword matching was case-sensitive

### Changed

- `BaseScanner.scan()` signature now accepts optional `context: ScanContext | None` parameter across all 10 scanner/check implementations
- `ScanEngine` creates and propagates `ScanContext` between sequential scanner runs
- Nuclei scanner class docstring updated to describe the three-phase strategy
- Database schema remains v5 (no migration needed)

## 0.4.0 — 2026-03-22

### Added

- Nuclei directory-based template selection (`template_dirs` option) for precise control over which template categories to scan
- `DEFAULT_TEMPLATE_DIRS` constant covering 6 template categories that complement other HARIS scanners (exposures, exposed-panels, vulnerabilities, default-logins, takeovers, DAST)
- Template Directories, Exclude Tags, and Max Host Errors options in the Nuclei scanner UI panel
- Structured rotating file logger (`data/logs/haris.log`, 5 MB rotation, 3 backups)
- Nuclei command and exit status logging for scan debugging
- `scanner_results` DB table (schema v5) to persist per-scanner errors and metadata
- 10 new nuclei scanner unit tests

### Fixed

- Nuclei returning 0 findings against Cloudflare-protected HTTPS sites — added `-fh2` flag for HTTP/2 negotiation
- Nuclei host-skipping after 30 errors — disabled via `-nmhe` (no max-host-error) flag
- Nuclei loading entire 12k+ template repo when TemplateManager repo paths merged with `template_dirs` — `template_dirs` now takes precedence
- Nuclei templates using JavaScript/flow protocol stages filtered out by `-pt http,ssl` — removed `-pt` flag (template directories already scope protocol)
- Nuclei scan timeout too short for large template sets — raised default from 600s to 1800s
- Nuclei flaky connections causing missed findings — added `-retries 2`
- Wapiti scanner crash on integer severity levels, None parameters, and list wstg fields
- Nikto tuning handling when value is a list vs string
- Scanner options accordion panels not expanding on click — replaced `<details>` elements with div-based JS toggle for browser compatibility
- Label accessibility warnings on template form (8 violations)
- Scanner results tab showing no data for completed scans (legacy fallback reconstruction)

### Changed

- Builtin-03 "Full OWASP Top 10" uses `template_dirs` instead of tag-based selection, includes all severity levels
- Scanner option panels now render server-side based on profile (Jinja) instead of relying solely on JS
- Database schema upgraded to v5

## 0.3.0 — 2026-03-21

### Added

- Vertical left sidebar navigation on desktop, replacing the horizontal top bar; mobile top bar with hamburger preserved
- HARIS logo enlarged and moved to sidebar header
- "Scan Again" from website detail page now pre-populates the New Scan form with the previous scan's URL, profile, rate limit, excluded paths, and auth settings
- Scanner Templates page now lists all configured sources immediately, even before a first update ("Never updated" state shown for uninitialised sources)
- `templates/` directory added to Docker volume mounts so downloaded template files and metadata persist across container rebuilds
- Named Docker volume `nikto-data` for `/opt/nikto/` so Nikto database updates survive image rebuilds

### Fixed

- "Please enter a URL" browser popup appearing even after entering a valid URL on the New Scan form — replaced `type="url"` browser validation with custom JS validation that accepts both `http://` and `https://`
- Scanner Templates page "Templates" count and "Last Updated" columns not refreshing after an update — page now reloads automatically after a successful update
- Nikto template integration completely reworked: previously tried to clone the Nikto repo redundantly (Nikto is already installed in the Docker image) and used the wrong `-useproxy` flag; now runs `git pull` on the existing `/opt/nikto/` installation to keep databases current with no extra scanner flags needed
- Per-source Update button now correctly targets only the selected source instead of all sources for that scanner
- Pagination Next/Previous buttons loading nothing on click: dashboard scan list now uses a proper `<table>/<tbody>` container so `<tr>` rows render correctly; pagination `hx-target` changed from hardcoded `#scan-table-body` to `closest tbody` so buttons work on both the Dashboard and the Scans page
- `per_page` value now forwarded in pagination button URLs to keep page boundaries consistent
- White HARIS logo invisible in light mode — fixed with stacked `drop-shadow` CSS filters creating a visible dark outline
- `templates/` gitignore pattern anchored to repo root (`/templates/`) to avoid accidentally ignoring `src/templates/` and `src/web/templates/`

### Changed

- Default scan list page size reduced from 20 to 5
- Nikto template source changed from `source_type: git` (redundant clone) to `source_type: local` pointing at `/opt/nikto/`
- `NiktoTemplateAdapter.get_scanner_options()` now correctly returns `{}` — Nikto reads its own database directory natively, no extra flags required

## 0.2.0 — 2026-03-17

### Added

- Reusable scan configuration templates with per-scanner options (Nuclei tags/severity, Nikto tuning/plugins, Nmap ports/script categories, Wapiti modules/scope)
- 5 built-in default templates: Quick Surface Scan, Pre-Launch Audit, Full OWASP Top 10, Regression Check, Compliance Audit
- Unified Templates page (`/templates`) with two tabs: Scan Configurations and Scanner Templates
- Template create/edit form with scanner-specific options accordion
- Template selector on New Scan page that auto-fills form settings
- Settings page (`/settings`) with LLM, scanner, and database overview
- Visual timeline on website detail page showing risk posture changes
- Template and Scanners columns in website scan history table
- Paginated, filterable scan history on dashboard (HTMX-powered)
- "Compare Scans" chat preset in the LLM Q&A panel
- LLM chat context enrichment with template metadata
- Extended scan filters: by template and scanner name

### Changed

- Navigation restructured: Dashboard, Websites, Scans, Templates, New Scan (CTA button)
- Dashboard redesigned with paginated scan table replacing static findings list
- Database schema upgraded to v4 (`scan_config_templates` table, `template_id` on scans)
- `ScanRunner` accepts `scanner_options` for template-driven scanner configuration

## 0.1.0 — 2026-03-13

Initial release.

- CLI and web dashboard for running scans
- Scanner integrations: Wapiti, SSLyze, Nmap, Nikto, Nuclei
- Built-in checks: headers, TLS, cookies, CORS, info disclosure, sensitive paths
- Cross-tool finding correlation and deduplication
- Business-risk translation and remediation planning
- OWASP Top 10 (2025) mapping
- Scan profiles: quick, pre-launch, full, regression, compliance
- Report formats: Markdown, JSON, HTML
- LLM-powered Q&A, enrichment, triage, attack chain detection, variant analysis
- Jinja2-based prompt templates
- Scanner template management (Nuclei, Nikto, Nmap, Wapiti)
- SQLite scan history with session persistence
- Docker Compose support
