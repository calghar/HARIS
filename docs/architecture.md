# Architecture

## Overview

HARIS follows a pipeline architecture:

```txt
Configuration -> Target -> Scanners -> Findings -> Enrichment -> Reports
```

## Layers

### 1. Configuration (`src/config/`)

The configuration layer loads settings from three sources (in priority order):

1. **Programmatic overrides** (CLI arguments)
2. **Environment variables** (`HARIS_*`)
3. **YAML config file** (`config/*.yaml`)

This ensures sensitive values (credentials, tokens) never need to be committed to files.

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

## Data Flow

```txt
YAML Config + Env Vars + CLI Args
        |
        v
    Config object
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
    ScanSession (all findings, metadata)
        |
        v
    Reporter.generate(session) --> report files
```
