# Changelog

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
