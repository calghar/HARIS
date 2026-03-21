# Changelog

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
