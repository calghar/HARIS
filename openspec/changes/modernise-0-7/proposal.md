## Why

HARIS reports too many false positives, has verified security holes in its own web layer, ships a package that cannot be published, and runs vulnerable dependencies. Open-source competitors now verify findings by replay or exploitation and cover AI systems.

## What Changes

- **BREAKING** Rename Python package `src` to `haris` (`src/haris/`), CLI `haris`, remove the `scripts` package; single-source version.
- **MODIFIED** Dependencies upgraded to latest stable (starlette 1.x, anthropic 2.x, openai 3.x, cryptography 50, authlib, mypy 2.x); pip-audit blocking.
- **BREAKING** SQLite schema moves to a migration framework; session and verification tokens stored hashed; `finding_id` becomes a stable fingerprint.
- **MODIFIED** Core pipeline: correlation by CWE and canonical class, correlated findings drive risk and reports, confidence weights risk, baseline/ignore file, scan diff, `--fail-on`, exit codes, parallel scanners, scoped HTTP client.
- **MODIFIED** Built-in checks: soft-404 baseline, content validators, confidence levels, header/cookie/TLS corrections.
- **MODIFIED** Scanner adapters: bug fixes, argv allow-list, process-group timeouts, credential redaction, modern Nuclei flags.
- **BREAKING** Web layer: auth and ownership on all routes, app-wide CSRF, SSRF-safe targets, persisted job queue, API tokens, `/api/v1`.
- **MODIFIED** LLM layer: validated structured output, redaction, untrusted-data fencing, budgets.
- **ADDED** Verification stage (replay, LLM verdict, opt-in sandboxed agentic validator).
- **ADDED** AI-system security module with garak and promptfoo adapters.
- **ADDED** SARIF, CSV, JUnit outputs; benchmark harness; community, CI and release files.

## Capabilities

### Modified Capabilities
<!-- No capability specs exist yet; every capability below is introduced as ADDED. -->

### New Capabilities
- `finding-identity`: stable fingerprints, correlation, tiers, confidence and risk weighting.
- `scoped-http`: scope, rate limit, request cap, redirect and SSRF rules for every outbound request.
- `verification`: replay verifier, LLM case verdict and agentic validator.
- `ai-security`: discovery and checks for LLM, RAG, MCP and agent endpoints, plus external adapters.
- `web-access-control`: authentication, ownership, CSRF and target authorisation for the dashboard and API.

## Blast radius

Grep-confirmed readers of the changed surfaces:
- `Finding` and `ScanSession` models: `src/core/*`, `src/models/*`, `src/db/store.py`, `src/reporting/*`, `src/llm/*`, `src/web/app.py`, 21 test files.
- DB schema and tokens: `src/db/store.py`, `src/auth/service.py`, `src/auth/router.py`, `src/web/templates/profile.html`.
- Package rename: every module import, `pyproject.toml`, `Dockerfile`, CI workflows, docs.
- Do-not-touch: external tool CLIs; `config/scanner_data.yaml` semantics except where a task names it.

## Impact

- Import paths and CLI name change (pre-1.0, accepted by the maintainer).
- Existing SQLite databases migrate in place; token columns are hashed in place on first start and active sessions stay valid.
- JSON report gains `verification`, `fingerprint`, `confidence_score`; old fields stay.
- New optional dependencies: Docker (agent mode), garak and promptfoo (adapters, external CLIs).
