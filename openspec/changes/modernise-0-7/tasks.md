## 1. Barrier and foundation

- [x] 1.1 Generated `tests/features/*.feature` with `openspec-bdd generate`; step bindings land with each workstream's tests, and every scenario maps to at least one test
- [x] 1.2 Renamed package `src` to `haris`; 469 tests pass (regression guard for all later tasks)
- [x] 1.3 Upgraded dependencies; `pip-audit` clean; ruff, mypy and pytest pass
- [x] 1.4 Added migration framework (yoyo) with `0001` baseline, hashed tokens, repository split of `store.py`; regression test: a 0.6.2 database opens and its scans, templates and users read back unchanged

## 2. Parallel workstreams (disjoint ownership, each in its own worktree)

- [x] 2.1 Core pipeline (`core/`, `models/`, `net/`, `ignore`, `diff`): finding identity, correlator, risk, scoped client, exit codes, baseline file; regression test: 0.6 JSON reports still load
- [x] 2.2 Built-in checks (`checks/`): soft-404 baseline, validators, confidence, TLS and cookie fixes, new checks; regression fixtures: SPA catch-all and WAF page produce zero path findings
- [x] 2.3 Scanner adapters (`scanners/`, `templates/`, `resources/config/scanners`): bug fixes, argv allow-list, process-group timeouts, redaction, Nuclei flags; golden fixtures from real tool output
- [x] 2.4 Web, auth, API (`web/`, `auth/`): routers, access control, SSRF guard, job queue, API tokens, `/api/v1`, CSP; TestClient tests for every route
- [x] 2.5 LLM layer (`llm/`): structured output, redaction, fencing, budgets, config-driven models
- [ ] 2.6 Verification stage (`verify/`, `agent/`): replay verifier, LLM verdict, sandboxed agent behind two flags
  - [x] Part 1: replay verifier, oracles `reflection`, `error_signature`, `timing`, `header_presence`, `canary`, LLM verdict, `--verify`
  - [x] Deferred: oracles `content_validator` and `soft404` (need `haris.checks.baseline` and `haris.checks.validators`); `sensitive_file` findings stay `unverified` until they are registered in `haris/verify/oracles.py`
  - [ ] Deferred: sandboxed agent (`haris/agent/`), `agent` stage and `stage_log`
- [ ] 2.7 AI-security module (`ai_security/`, `scanners/garak_scanner.py`, `scanners/promptfoo_scanner.py`)
- [x] 2.8 Reporting (`reporting/`): SARIF, CSV, JUnit, JSON schema, escaped HTML, CI integrations
- [x] 2.9 Benchmark harness (`bench/`): targets, ground truth, scorer, nightly workflow

## 3. Integration and release

- [x] 3.1 Merged workstreams in dependency order; full gate green in chunks; benchmark run with replay verification and scored per tier (juice_shop, dvwa, webgoat: `bench/results/2026-11-11-202728`); verdict threshold calibration and a baseline comparison moved to Phase 6 (4.2, 4.12)
- [x] 3.2 Independent code, security, structural and simplification reviews; findings fixed (structural refactors deferred to 4.14 to 4.17)
- [ ] 3.3 README and docs updated; counts verified against code; prose gate passed; CHANGELOG complete
- [ ] 3.4 Community files, CI hardening, SBOM, image scan, release automation, Dockerfile rewrite
- [ ] 3.5 Tagged 0.7.0 after maintainer approval of commit messages

## 4. Phase 6: follow-ups and LiteLLM on Bedrock (implemented on the GitHub-only machine; specs written first)

- [ ] 4.1 Replaced the `anthropic` and `openai` SDKs with LiteLLM routed to Bedrock models; model ids and capabilities stay in config; credentials come from the AWS credential chain; no provider key variables remain in code, docs or CI; regression test: every backend call in `llm/` goes through one LiteLLM wrapper
- [ ] 4.2 Calibrated `verify.llm.abstain_below` on the labelled bench set through the Bedrock backend (default 0.7 is uncalibrated)
- [ ] 4.3 Raised replay coverage for Wapiti findings (SQL injection `error_signature`, XSS `reflection`, `command_injection`, `path_traversal`, `open_redirect`, `ssrf` stay `unverified` on DVWA); target 95% precision in the replay-verified tier on a meaningful count of verified findings
- [ ] 4.4 Seeded the WebGoat crawl so Wapiti reaches the lesson endpoints (it ends in 3.6 s today; recall .571)
- [ ] 4.5 Live-tested Wapiti 3.3.x `information_disclosure` on DVWA in the sandbox and dropped the exclusion only on a clean run
- [ ] 4.6 Bounded or skipped nuclei phase 2 (531 s on Juice Shop) and sslyze on plain HTTP (`ERROR_NO_CONNECTIVITY` leaves every bench session `incomplete`)
- [ ] 4.7 Aligned `OWASP_MAPPINGS` with the `cleartext_password_submission` class (reports get A04 only through the Wapiti tag today)
- [x] 4.8 Refuted redirect-based catch-all hosts: `baseline.judge` returns early for non-2xx although design D3 describes a 3xx rule
- [ ] 4.9 Classified nikto "This might be interesting" findings (Juice Shop `/ftp` stays a miss) and the remaining nikto and nuclei noise (`gocd-encryption-key` on the `security.txt` prefix route, WebGoat `trace.axd` header)
- [x] 4.10 Gave replay its own soft-404 control timeout (it uses the 30 s `policy.timeout_s` today), replayed every PoC request (only the first today), and kept the skip note in `errors` on a failed scan (`finish()` can drop it)
- [ ] 4.11 Live-verified the unverified surfaces: ZAP end to end, garak and promptfoo output shapes, `action.yml` and the GitLab template, the web UI in a browser, the web agent with real Docker, XXE out of band
- [ ] 4.12 Ran the benchmark with a baseline profile and recorded the scores with raw artifacts
- [ ] 4.13 Closed the DNS-rebinding window for external scanners: pin the vetted IP per tool (nuclei, nmap, nikto, sslyze, Wapiti) or run them in a network that blocks private ranges; the 0.7.0 fix only re-vets the host right before each tool starts (security review H-2)
- [ ] 4.14 Replaced decorator-based registration with explicit built-in maps for checks, scanners and oracles, removed the second scanner registry and the trigger-only imports (structural review S-01)
- [ ] 4.15 Split `cli.py` into parser, command handlers and scan orchestration modules, with `main` as dispatch only (S-02)
- [ ] 4.16 Moved Nuclei template selection and argv construction out of `nuclei_scanner.py` into a data-only module (S-05)
- [ ] 4.17 Split `bench/run.py` into target preparation and authentication, and command execution, with CLI dispatch left in `run.py` (S-06)
