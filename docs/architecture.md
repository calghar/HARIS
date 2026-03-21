# Architecture

## Overview

HARIS follows a pipeline architecture:

```txt
Configuration -> Target -> Scanners -> Findings -> Enrichment -> Reports
```

## Layers

### 1. Configuration (`src/config/`, `src/models/scan_config_template.py`)

The configuration layer loads settings from three sources (in priority order):

1. **Programmatic overrides** (CLI arguments)
2. **Environment variables** (`HARIS_*`)
3. **YAML config file** (`config/*.yaml`)

This ensures sensitive values (credentials, tokens) never need to be committed to files.

**Scan Configuration Templates** add a fourth source: reusable presets stored in the SQLite database (`scan_config_templates` table, schema v4).  A template bundles a scan profile with per-scanner option overrides (Nuclei tags/severity, Nikto tuning/plugins, Nmap ports/script categories, Wapiti modules/scope, etc.).  When a scan is started with a template, its `template_id` is recorded on the scan session.  Five built-in templates are seeded on first run.

### 2. Target Model (`src/core/target.py`)

The `Target` dataclass represents the system under test:

- `base_url`: Root URL of the application
- `scope`: Authorised testing boundaries (domains, paths, rate limits)
- `auth`: Optional authentication configuration

The `Scope` object is the enforcement mechanism for lawful testing. Every scanner must check `scope.is_url_in_scope()` before making requests.

### 3. Scanner Interface (`src/core/scanner.py`)

`BaseScanner` defines the contract for all scanners:

```python
configure(options) -> None
scan(target) -> ScannerResult
parse_results(raw_output) -> list[Finding]
```

Two categories of scanners exist:

- **External tool adapters** (`src/scanners/`): Wrap CLI tools like Wapiti, SSLyze, Nmap. They shell out to the tool, capture output (JSON/XML), and parse it.
- **Custom checks** (`src/checks/`): Pure Python checks that use `requests` or `ssl` directly. No external dependencies.

### 4. Finding Model (`src/core/finding.py`)

All scanners produce `Finding` objects with a unified schema:

- Identity: title, description, finding_id
- Classification: severity, confidence, OWASP category, CWE ID
- Location: URL, parameter, HTTP method
- Evidence: raw evidence, example request, response snippet
- Remediation: suggested fix, references

### 5. OWASP Mapping (`src/core/owasp.py`)

A lookup table maps vulnerability keywords and CWE IDs to OWASP Top 10 (2025) categories. The engine auto-enriches findings with OWASP categories based on scanner tags.

### 6. Orchestration Engine (`src/core/engine.py`)

`ScanEngine` coordinates the scan:

1. Iterates through registered scanners
2. Configures each scanner with its options
3. Runs each scanner sequentially (to respect rate limits)
4. Collects findings into a `ScanSession`
5. Deduplicates and sorts findings
6. Auto-maps OWASP categories

### 7. Reporting (`src/reporting/`)

`BaseReporter` defines `generate(session) -> str`. Three implementations:

- **MarkdownReporter**: Human-readable report with executive summary, methodology, findings by category, and detailed per-finding sections
- **JSONReporter**: Machine-readable structured output
- **HTMLReporter**: Self-contained HTML wrapping the Markdown report

### 8. Web Dashboard (`src/web/`)

The FastAPI web application serves a multi-page dashboard:

- **Dashboard** (`/`): Paginated scan history with HTMX filters (website, severity), quick actions, and a recently scanned sidebar.
- **Websites** (`/websites`): Per-target overview. Detail pages show a visual timeline of risk posture changes and finding deltas.
- **Scans** (`/scans`): Filterable by website, severity, template, and scanner name.
- **Templates** (`/templates`): Two-tab hub -- *Scan Configurations* (CRUD for saved presets) and *Scanner Templates* (manage external template sources, trigger updates).
- **New Scan** (`/scan/new`): Template selector dropdown auto-fills the form; "Save as Template" persists current settings. Per-scanner advanced options are collapsible.
- **Settings** (`/settings`): Read-only overview of LLM backends, available scanners, and database info.

Navigation order: Dashboard | Websites | Scans | Templates | New Scan (CTA button style).

## Data Flow

```txt
YAML Config + Env Vars + CLI Args + Scan Config Template (optional)
        |
        v
    Config object (template overrides merged)
        |
        v
    Target + Scope
        |
        v
    ScanEngine.run(target)
        |
        +-- Scanner 1 --> ScannerResult --> [Finding, Finding, ...]
        +-- Scanner 2 --> ScannerResult --> [Finding, Finding, ...]
        +-- Scanner N --> ScannerResult --> [Finding, Finding, ...]
        |
        v
    Deduplication + OWASP enrichment
        |
        v
    ScanSession (all findings, metadata, template_id)
        |
        v
    Reporter.generate(session) --> report files
```

### Database Schema

The SQLite database (schema v4) stores:

- `scans` -- Scan sessions with a `template_id` column linking to the template used
- `findings` -- All findings per scan
- `scan_config_templates` -- Reusable scan configuration presets
- `llm_enrichments`, `attack_chains`, `triaged_findings`, `false_positive_assessments`, `executive_priorities` -- LLM enrichment data

## Scan Configuration Templates

Reusable presets that bundle a scan profile with per-scanner option overrides. Five built-in templates are seeded on first run.

| Template | Profile | Key Options |
| -------- | ------- | ----------- |
| Quick Surface Scan | `quick` | Built-in checks only |
| Pre-Launch Audit | `pre-launch` | Nmap common ports, Wapiti folder scope, LLM enrichment |
| Full OWASP Top 10 | `full` | All scanners, Nuclei CVE/misconfig tags, Nikto tuning |
| Regression Check | `regression` | Headers + TLS + misc only |
| Compliance Audit | `compliance` | Nmap + TLS + info disclosure, LLM enrichment |

Per-scanner options per template:

- **Nuclei**: `tags`, `severity`, `rate_limit`, `timeout`
- **Nikto**: `plugins`, `tuning`, `timeout`
- **Wapiti**: `modules`, `scope`, `max_scan_time`, `max_links`, `timeout`
- **Nmap**: `ports`, `script_categories`, `timeout`
- See `src/models/scan_config_template.py` for the full option set.

**API**: `GET/POST /api/scan-templates`, `PUT/DELETE /api/scan-templates/{id}`, `POST /api/scan-templates/{id}/set-default`
**Web UI**: `/templates` → *Scan Configurations* tab — create, edit, clone, delete, set default.

## Scanner Template Management

External scanner template files are stored in `./templates/{scanner}/{source_name}/` and tracked via `templates/metadata.json`. Sources are configured in `config/default_config.yaml` under `template_sources:`.

| Scanner | Source type | How templates are used |
| ------- | ----------- | ---------------------- |
| Nuclei | `git` — clones `nuclei-templates` repo | Template paths passed as `-t` flags |
| Nikto | `local` — `git pull` on existing `/opt/nikto/` | Updates `db_*` files in-place; Nikto reads them automatically |
| Nmap | None — drop `.nse` files in `templates/nmap/custom/` | Custom scripts passed as `--script` args |
| Wapiti | No template support | — |

**CLI**: `python scripts/run_scan.py update-templates [--scanner nuclei] [--force] [--list]`
**Web UI**: `/templates` → *Scanner Templates* tab — per-source status and update trigger.
**API**: `GET /api/templates/status`, `POST /api/templates/update`

The `./templates/` directory and the `nikto-data` Docker volume are both persisted so updates survive container rebuilds.
