## 1. Barrier and foundation

- [x] 1.1 Generated `tests/features/*.feature` with `openspec-bdd generate`; step bindings land with each workstream's tests, and every scenario maps to at least one test
- [x] 1.2 Renamed package `src` to `haris`; 469 tests pass (regression guard for all later tasks)
- [x] 1.3 Upgraded dependencies; `pip-audit` clean; ruff, mypy and pytest pass
- [x] 1.4 Added migration framework (yoyo) with `0001` baseline, hashed tokens, repository split of `store.py`; regression test: a 0.6.2 database opens and its scans, templates and users read back unchanged

## 2. Parallel workstreams (disjoint ownership, each in its own worktree)

- [ ] 2.1 Core pipeline (`core/`, `models/`, `net/`, `ignore`, `diff`): finding identity, correlator, risk, scoped client, exit codes, baseline file; regression test: 0.6 JSON reports still load
- [ ] 2.2 Built-in checks (`checks/`): soft-404 baseline, validators, confidence, TLS and cookie fixes, new checks; regression fixtures: SPA catch-all and WAF page produce zero path findings
- [ ] 2.3 Scanner adapters (`scanners/`, `templates/`, `resources/config/scanners`): bug fixes, argv allow-list, process-group timeouts, redaction, Nuclei flags; golden fixtures from real tool output
- [ ] 2.4 Web, auth, API (`web/`, `auth/`): routers, access control, SSRF guard, job queue, API tokens, `/api/v1`, CSP; TestClient tests for every route
- [ ] 2.5 LLM layer (`llm/`): structured output, redaction, fencing, budgets, config-driven models
- [ ] 2.6 Verification stage (`verify/`, `agent/`): replay verifier, LLM verdict, sandboxed agent behind two flags
- [ ] 2.7 AI-security module (`ai_security/`, `scanners/garak_scanner.py`, `scanners/promptfoo_scanner.py`)
- [ ] 2.8 Reporting (`reporting/`): SARIF, CSV, JUnit, JSON schema, escaped HTML, CI integrations
- [ ] 2.9 Benchmark harness (`bench/`): targets, ground truth, scorer, nightly workflow

## 3. Integration and release

- [ ] 3.1 Merged workstreams in dependency order; full gate green in chunks; benchmark run against baseline; verdict threshold calibrated
- [ ] 3.2 Independent code, security, structural and simplification reviews; findings fixed
- [ ] 3.3 README and docs updated; counts verified against code; prose gate passed; CHANGELOG complete
- [ ] 3.4 Community files, CI hardening, SBOM, image scan, release automation, Dockerfile rewrite
- [ ] 3.5 Tagged 0.7.0 after maintainer approval of commit messages
