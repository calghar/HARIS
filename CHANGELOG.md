# Changelog
<!--markdownlint-disable MD024-->

## 0.6.3 — Unreleased

### Added

- Added an opt-in sandboxed exploit validator (`haris.agent`) behind `--agent` and `--i-have-authorization`; a finding reaches `exploit_validated` only after the PoC is re-executed and the oracle is positive
- Finding identity: every finding has a stable `fingerprint` (SHA-256 over CWE, vulnerability class, normalised URL, method and parameter), a per-sighting `observation_id`, a `confidence_score`, a `verification` tier and a `suppression`; 0.6.x JSON reports still load
- Vulnerability classes in `vuln_classes.yaml` and per-scanner confidence priors in `confidence.yaml`
- Correlator merges the same finding across scanners by fingerprint, scores consensus confidence and no longer mutates its input
- `.haris-ignore.yaml` (`--ignore-file`) suppresses findings by fingerprint or class with a required reason, author and expiry date
- `--fail-on SEVERITY`, `--baseline REPORT.json`, `--allow-private`, `--parallel N` and `haris diff OLD NEW` (new, fixed, not_retested, unchanged)
- Exit codes: 0 clean, 1 findings at `--fail-on`, 2 incomplete, failed or cancelled scan, 3 usage error
- Scan state (`completed`, `incomplete`, `failed`, `cancelled`) and partial results saved to `session.partial.json` and the database after each scanner
- `haris.net.ScopedClient`: scope, SSRF (pinned resolution, private ranges blocked unless `--allow-private`), rate limit, request cap, per-hop redirect checks, retries and a redacted request log; exposed as `ScanContext.http`
- SSRF pre-flight before any scanner starts, and a per-tool request rate (`ScanContext.tool_rate_rps`)
- SARIF 2.1.0 (`sarif`), CSV (`csv`) and JUnit XML (`junit`) report formats for `--formats`; SARIF carries partial fingerprints, web request and response, `suppressions` and, with `--baseline`, `baselineState`
- JSON report adds `scan_state`, `scanner_status` and `correlated` (with `sources`); published JSON Schema at `src/haris/resources/schema/report.schema.json`
- GitHub Action (`action.yml`) and GitLab CI template (`integrations/gitlab/templates/haris.yml`); see `docs/integrations.md`
- Added an admin-only "Exploit validation" option to web scans (`agent=1`): it needs a verified ownership proof for the host, `HARIS_AGENT_DISABLED` unset and verify not `off`, and is re-checked when the queued scan starts
- Added a soft-404 baseline (`checks/baseline.py`) and content validators (`checks/validators.py`): SPA catch-all and WAF block pages no longer produce sensitive-path or debug-endpoint findings, `.env` must look like `KEY=VALUE` and `.git/config` must contain `[core]`
- Added built-in checks `sri_checks`, `cache_checks`, `method_checks` (OPTIONS and TRACE), `redirect_checks` (open redirect), `graphql_checks` (introspection), `openapi_checks`, `listing_checks` (directory listing) and `dns_checks` (CAA, SPF, DMARC), each with a class in `vuln_classes.yaml` and a prior in `confidence.yaml`
- Added CSP and HSTS quality findings (`unsafe-inline`, `unsafe-eval`, wildcard sources, missing `object-src` or `base-uri`, short `max-age`, missing `includeSubDomains`)
- Added a ruff `TID251` rule that bans `requests`, `httpx` and `urllib3` outside `haris/net`; `llm/providers.py`, `bench/` and `tests/` are ignored per file
- Added vulnerability classes `command_injection` (CWE-78), `csrf` (CWE-352) and `unrestricted_upload` (CWE-434) for Wapiti findings, and restored the DVWA command-injection, CSRF and upload entries and the Juice Shop `/ftp` listing entry in the benchmark ground truth
- Added a verification stage (`haris.verify`) that replays each finding's request through `ScopedClient` with a control, applies per-class oracles (`reflection`, `error_signature`, `timing`, `header_presence`, `canary`) and moves the tier only to `replay_verified` or `refuted`
- Added `--verify {off,replay,llm}` (default `replay`); `llm` adds a case-level LLM verdict whose quoted spans are checked against the evidence and which changes the score, never the tier
- Added `verify.yaml` for the request cap, timing delay, error signatures, valid header values and LLM abstain threshold
- Added `ai_security` check (`haris.ai_security`): finds OpenAI-compatible, Ollama, vLLM, TGI, Triton, LangServe, Flowise, Open WebUI, Gradio, MLflow, Ray, ComfyUI and Jupyter endpoints, chat widgets and MCP servers behind the soft-404 baseline; passive checks cover unauthenticated inference and admin APIs, provider keys, system prompts and model settings in bundles, verbose provider errors, CORS on chat APIs and plaintext MCP
- Added read-only MCP analysis (`initialize`, `tools/list`, and `resources/list` or `prompts/list` when advertised) with static checks for injected tool text, hidden Unicode, free-form parameters and toxic capability pairs; `tools/call`, `resources/read` and `prompts/get` are never sent
- Added active AI probes behind `--ai-active` and `--i-have-authorization` (exit 3 without the second flag): canary injection, system prompt leak, output-handling XSS marker, a small jailbreak set, a rate-limit burst and a `max_tokens` check; payloads come only from `ai_probes.yaml`, limited by `ai.max_prompts` (50) and `ai.max_tokens_per_prompt` (256), and a finding reaches `replay_verified` only after a repeat with a fresh canary
- Added `garak` and `promptfoo` scanners (not vendored; Apache-2.0 and MIT) that run under the same flags and map failures to OWASP LLM Top 10 2026 ids; added OWASP LLM Top 10 2026, Agentic Top 10 and MCP Top 10 (`[UNVERIFIED]`, beta) tables and the `ai-security` profile; see `docs/ai_security.md`
- Added the `sri_checks`, `cache_checks`, `method_checks`, `redirect_checks`, `graphql_checks`, `openapi_checks`, `listing_checks` and `dns_checks` checks to the `quick`, `pre-launch` and `full` profiles
- Changed OWASP LLM Top 10 ids to the 2026 list (renumbered; System Prompt Leakage became Hidden Context Exposure, LLM08:2026)
- Added `ScanSession.stage_log` and `Finding.agent_annotation` as persisted fields (migration `0008_agent_fields`); the JSON report adds `stage_log` and `agent_annotation`, SARIF adds `properties.agentAnnotation`, and the Markdown and HTML reports show the annotation in a fenced block
- Added `soft404` and `content_validator` verification oracles; `sensitive_file` findings can now reach `replay_verified` or `refuted`
- Added `haris bench score REPORTS TRUTH.yaml [--baseline DIR] [--out DIR]`, the same scorer as `python -m haris.bench score` (exit 3 on a missing path)
- Added `verify` to web scan requests and `HARIS_WEB_VERIFY_DEFAULT` (default `replay`)
- Added a login step to `bench/run.py` for DVWA and WebGoat (session passed to `haris` through `--config` and `HARIS_AUTH_HEADER`) and moved the external ground-truth class ids to ids HARIS emits; every seeded weakness is an entry, so recall shows what HARIS misses
- Added an `ignore` list to benchmark ground truth (reported as an ignored count in `score.md`) and a per-target profile and extra `haris` args in `bench/run.py`; `--profile` is now optional
- Added `ScopedClient.stream()` (bounded read with a `truncated` flag) and a per-call `timeout_s`; replay no longer swaps `NetworkPolicy.timeout_s`, and the AI module probes `/sse` with GET instead of HEAD
- Added scanner options `external_endpoint` and `internal_endpoint` so Wapiti's out-of-band checks can use a local callback receiver; the benchmark runs a `callback` fixture service and no longer contacts `wapiti3.ovh` (`log4shell` is always dropped)
- Added a scope and SSRF pre-flight on the discovered chat URL before `garak` or `promptfoo` starts; a failure is a scanner error and the tool is not started, and `docs/ai_security.md` lists what is not enforced on their own requests
- Added one `agent.refused` audit row for each refused web agent request, with the user id, target host and a reason code (`not_admin`, `no_verified_proof`, `agent_disabled`, `verify_off`)
- Added an optional `zap` scanner that runs the ZAP Automation Framework (spider, passive wait, active scan, report) and reads the `traditional-json` report; it is disabled by default, is in no profile, and runs with `--scanners zap`. Not yet checked against a live ZAP
- Mapped common ZAP plugin ids to vulnerability classes and set the `zap` confidence prior to 0.6
- Added vulnerability class `cleartext_password_submission` (CWE-319) for Wapiti cleartext password forms, and mapped Nuclei `prometheus-metrics-detect` and `phpinfo-page-detect` to `sensitive_file`
- Added `--verify` to `bench/run.py`, passed through to `haris` for every target run
- Added `docs/verification.md` covering finding tiers, replay oracles, the soft-404 control and the uncalibrated LLM abstain threshold
- Added a CycloneDX SBOM, a Trivy image scan that fails on fixed HIGH and CRITICAL findings, and an OpenSSF Scorecard workflow with SARIF upload
- Added a security policy, the Contributor Covenant 2.1, a governance note, a roadmap, issue forms, a pull request template and `CODEOWNERS`
- Added an MkDocs Material configuration for the pages in `docs/`
- Added `HARIS_PUBLIC_URL`; when set, emailed verification and reset links use it as their only base
- Added `HARIS_ALLOWED_HOSTS`; when set, the web app rejects any other Host header
- Added `HARIS_COOKIE_SECURE` (`true`, `false` or `auto`) for the session and CSRF seed cookies
- Added `HARIS_SETUP_TOKEN`; `/auth/setup` answers 404 while it is unset

### Changed (packaging)

- Renamed package `src` to `haris` (`src/haris/`); project name `haris`; console script `haris` replaces `scripts/run_scan.py`; `python -m haris` works
- `config/` moved to `src/haris/resources/config/` and ships in the wheel; override with `HARIS_CONFIG` or `./config/` in the working directory
- Web logo served from `/static/haris_logo.png`; `/assets` mount removed
- `haris.__version__` read from package metadata; the web app reports it
- Added `itsdangerous` to the `web` extra (required by `SessionMiddleware`)
- Upgraded all dependencies to latest stable (starlette 1.10, fastapi 0.162, openai 3.46, anthropic 2.6, cryptography 50, authlib 1.9.5, urllib3 2.8, mypy 2.4, ruff 0.17); `pip-audit` reports no vulnerabilities and dependency floors match the patched versions
- `scanners` extra (sslyze, wapiti3) removed from `all` and declared conflicting with `web`; install both as isolated tools (`pipx`), as the Docker image now does under `/opt/tools`
- Removed the redundant `llm-openai`/`llm-anthropic` extras (both SDKs are core dependencies); dev tools moved from the `dev` extra to the `dev` dependency group (`uv sync` installs it)
- Documented minimum external tool versions in the README
- Dependabot uses the `uv` ecosystem and groups minor/patch updates
- Raised the documented Wapiti minimum to 3.3.2 and mapped its new categories `Stack Trace Disclosure` (`verbose_error`) and `CVE-2024-55591`; the flags, module names and session database that HARIS uses are unchanged, and `stacktrace_disclosure` now runs in the default module set
- Wapiti 3.3.2 sends one extra probe request per crawled directory to detect soft 404 pages, so the crawl can drop catch-all pages; `information_disclosure` stays excluded until a live run shows its 3.3 regex is safe
- Pinned third-party GitHub Actions by commit SHA, tested Python 3.13 and 3.14, skipped docker-marked tests in CI and added a coverage threshold input (default 70, not yet measured)
- Release tags build the sdist and wheel, publish to PyPI with attestations, push and sign `ghcr.io/<owner>/haris` with cosign, and open a GitHub Release from the matching changelog section; the tag must equal the project version
- Rewrote the container image: multi-stage, digest-pinned base, uid 10001, checksummed nuclei 3.11.1 and nikto 2.6.0, health check; compose adds memory and CPU limits and a read-only root, and no longer mounts a volume over nikto

### Fixed

- Fixed the benchmark runner failing a re-run with "expected one JSON report" and leaving earlier targets running; each invocation writes to a new `bench/results/<date>-<time>/` directory and each target is removed after its runs
- Fixed `haris --url HOST` failing every scanner pre-flight with "outside the authorised scope" for any host but `example.com`; the packaged config no longer sets `allowed_domains`, so scope defaults to the target host
- Fixed the profile page rendering a blank id for each session and failing to revoke it; sessions are now listed and revoked by token hash
- Fixed `haris --web` binding to every interface by default; `--host` now defaults to `127.0.0.1`
- Dropped all `pip-audit --ignore-vuln` entries; the audit and mypy CI jobs are now blocking
- Added `types-authlib` so mypy resolves authlib imports; import order in tests and doc snippets reformatted for ruff 0.17
- **Nuclei scanner Docker template persistence** — nuclei templates now persisted via `nuclei-data` volume across container rebuilds, avoiding 2GB+ re-download on every rebuild
- **Nuclei scanner Dockerfile reliability** — split nuclei install into two RUN layers: binary installation (fails hard on error) and template pre-fetch (allowed to fail). Unsupported architectures now fail build instead of silently continuing with broken scanner
- **Nuclei scanner template path validation** — added `_check_templates_available()` method with warning when template directory is missing; added workflow existence guard in `_resolve_targeted_selection()` to skip missing workflow files instead of passing invalid paths to nuclei
- **Nuclei scanner config validation** — added Pydantic schema validation (`_NucleiConfig`) for `config/scanners/nuclei.yaml` with warn-only error handling to catch type mismatches early
- **Nuclei scanner timeout defaults** — `timeout_per_request` now properly defaulted to 30 seconds in both `default_config.yaml` and `NucleiScanner.__init__()` instead of only as inline fallback
- Added clarifying comments to `config/scanners/nuclei.yaml` documenting that workflow paths are relative to nuclei's built-in template root
- A scan where every scanner fails no longer reports `EXCELLENT` and exit code 0
- Fixed the OpenAI backend choosing `max_completion_tokens` by `startswith("o")`; the capability table in `llm_models.yaml` now decides the token parameter and whether `temperature` is sent
- Fixed Anthropic requests failing on a `temperature` argument the installed SDK does not accept; temperature is sent only where the capability table allows it
- Fixed silent truncation to 25 or 30 findings in false-positive, attack-chain and triage prompts; every finding is sent in severity-ordered batches or marked `skipped_budget`
- Fixed Nikto runs that never parsed a report because Nikto appends `.json` to `-output`; the scanner now reads the file Nikto writes
- Fixed Nikto passing the non-existent `-useragent-extra`; auth headers go through `-Add-header`, and `-nocheck` stops Nikto's update check
- Fixed Nikto scanning `http://` for HTTPS targets; the target scheme is kept in the command and in finding URLs
- Fixed Nikto keywords matching inside words (`options` in X-Frame-Options, `eol` in geolocation); keywords now match whole words
- Fixed Wapiti 3.2.x findings losing tags and OWASP mapping; `wapiti.yaml` carries the real category names and unmapped categories fall back to `security_misconfiguration`
- Fixed Wapiti duplicating header, cookie, redirect and TLS findings; those modules are excluded through `excluded_modules`
- Fixed SSLyze crashing on `null` scan results; failed server scans are reported as scanner errors
- Fixed Nuclei reading templates from a hard-coded `/root/nuclei-templates`; the root comes from nuclei's own config
- Fixed Nuclei phase 2b re-running explicit tags and the phase 2a directories; the targeted phase excludes them and results are de-duplicated across phases
- Fixed Nuclei leaking the `-list` temp file; it is deleted in a `finally`
- Fixed the Nuclei severity filter hiding Phase 1 technology results; Phase 1 reports technologies, never findings
- Fixed a Nuclei timeout discarding results from earlier phases; the timed-out phase keeps its partial output and an error is recorded
- Fixed Nuclei, Nikto, Wapiti, Nmap and SSLyze timeouts leaving grandchild processes running; the whole process group is killed and partial stdout is kept
- Fixed `Authorization`, `Cookie` and API-key values appearing in scanner logs, evidence, `request_example` and `raw_data`; they are redacted
- Fixed unauthenticated access to `/api/llm/*`, scan-template reads and `/api/templates/status`; every route now requires a session unless listed in `haris.auth.public.PUBLIC_ROUTES`
- Fixed the open redirect on login `next`; only same-origin relative paths are followed
- Fixed OIDC linking a local account by an unverified email; `is_active` is enforced and `extract_role` handles string and list claims
- Fixed inline handlers and scripts that the nonce CSP blocked; all page scripts now live in `static/js/`
- Fixed role changes in the admin user table failing with a server error and the user table using a missing `user.id`
- Markdown and HTML reports escape every target-controlled value (titles, URLs, parameters, evidence) and the HTML report sets a CSP; raw HTML and `javascript:` links no longer pass through
- Reports list active findings only in the body and move refuted and suppressed findings to an appendix; each finding shows its verification tier and confidence, and risk posture `unknown` is shown
- Fixed built-in checks reporting `/admin`, `/.env` and debug paths on SPA catch-all and WAF hosts; a path is reported only when it differs from the host's not-found page and passes its validator
- Fixed `header_checks` reporting headers that do not apply (CSP on JSON, anything on 4xx/5xx) and the obsolete `X-XSS-Protection`; presence is judged by content type and final status
- Fixed duplicate and unrelated cookie findings from `header_checks` and `cookie_checks`; only session cookies are judged, once, in `cookie_checks` (SameSite maps to CWE-1275, not session fixation)
- Fixed `info_disclosure` matching "Express 2024", "Caused by: user" and "hackathon"; framework names need a version, `Caused by:` needs an exception class and comment markers are case-sensitive words
- Fixed `tls_checks` expiry and hostname checks that never ran; the certificate is read without verification, then verified separately, and TLSv1 and TLSv1.1 are probed independently
- Fixed the agent validator never confirming a reflected XSS first seen on `POST`; re-execution now sends the form body with a fresh `{marker}` under the proxy's destructive-content rules, also applied to percent-encoded text
- Fixed `outdated_server` CWE mapping on version endpoints and `X-Powered-By` context extraction (`raw_data` now carries the technology headers)
- Fixed the Wapiti adapter passing excluded paths as bare paths, which made Wapiti exit with code 2 (`Invalid argument for option -x`); they are now absolute URLs (`.*` becomes `*`) and regex entries are skipped with a warning
- Benchmark runner: Wapiti no longer scans DVWA's `/logout.php` and `/setup.php`; each benchmark target can carry its own excluded paths, added to the default exclusions in the generated `--config`.
- Fixed Wapiti scans hanging in the `information_disclosure` module (a ReDoS in Wapiti 3.2.10); the module is now excluded
- Fixed a Wapiti timeout or crash without a JSON report dropping all its findings; HARIS now recovers them from Wapiti's session database
- Fixed unset Wapiti endpoints falling back to `wapiti3.ovh`; SSRF and XXE run only when both endpoints are set, `log4shell` is always skipped, and unset endpoints use the target URL (internal) and `http://127.0.0.1:9/` (external)
- Fixed nikto crashing the Juice Shop benchmark target; the runner now bounds that run with `-maxtime 40s` through the generated `--config`, and the product default is unchanged
- Fixed the excluded-path labels on the new-scan form and the template form, which claimed `regex supported`; they now say one entry per line, a plain path or a trailing `.*`
- Fixed a web scan that requests the agent failing silently when Docker or the sandbox image is missing; the scan is accepted without that stage and records `[agent] skipped: docker unavailable` at submit and again at run time
- Fixed unclassified external findings on a catch-all host, such as nikto `/.psql_history`, staying active; replay now refutes a non-root GET when it matches the soft-404 control
- Fixed nikto being killed at the scanner timeout with 0 findings; it now runs with `-maxtime` 60 s below the timeout and writes its report (an `extra_args` `-maxtime` takes precedence)
- Fixed the Nuclei `sensitive_file` aliases to use the real template ids (`prometheus-metrics`, `phpinfo-files`), which the earlier names never matched; added `springboot-env` and `gocd-encryption-key`
- Fixed nikto missing-header, banner, CORS, robots.txt and phpinfo records reporting as unclassified; they now map to `missing_header`, `banner_disclosure`, `cors_misconfiguration` and `sensitive_file`, and replay checks the header named in a nikto title
- Fixed the DVWA, Juice Shop and WebGoat ground truth: blind SQL injection is `sqli_error`, WebGoat gains a stack-trace entry, and four nikto notes are ignored
- Fixed saved scans reloading with the default scope: excluded paths, rate limit, request cap, methods and redirect limits are now stored, and older rows without a scope still load
- Fixed a failed result write leaving a queue slot taken, which stopped later scans from starting
- Fixed an admin-disabled account coming back through the verification email; resend and consume refuse it, and only a `registration` token activates a user
- Fixed login limits living in process memory and covering only login; the same 5 attempts per 60 seconds are stored per IP and per email for login, register and resend
- Fixed OIDC first login creating a user outside `HARIS_ALLOWED_EMAIL_DOMAINS`
- Fixed login answering an unknown or inactive account before any password check
- Fixed a password change leaving other sessions signed in, and admin deactivation leaving sessions signed in
- Fixed the new-scan form listing every user's template names
- Fixed `/auth/setup` creating an administrator without a secret and allowing a second concurrent administrator
- Fixed web templates and scan starts accepting unvalidated `scanner_options`: unknown keys, unsafe endpoint URLs and web `extra_args` of `-fr` or `-followredirects` return HTTP 422, and `active` and `authorised` are dropped
- Fixed external scanners starting after the target name resolved to a blocked address; each tool is checked again right before it starts (the tool still resolves the name itself afterwards)
- Fixed `excluded_paths` accepting invalid, over-long or nested-quantifier regexes; they are compiled when supplied and rejected by the API (HTTP 422) and the CLI
- Fixed agent sandbox `exec` keeping full output and leaving a timed-out process in the container; output is capped at 1 MiB and the timeout kills that process
- Fixed Nuclei receiving discovered URLs that are out of scope or resolve to a blocked address
- Fixed an empty scanner status reporting risk posture `excellent`; it is now `unknown`
- Fixed promptfoo scheduling more tests than `max_prompts` when the cap is below the plugin count
- Fixed the agent sandbox tunnel cutting upstream replies that take more than 5 seconds, which broke timing-oracle validation
- Fixed web `dns_checks` options accepting `nameservers` and `dns_port`, which sent DNS queries to a caller-chosen server; the web policy allows only a bounded `dns_timeout`, and CLI and YAML config still set the server and port
- Fixed verification email using the request Host when `HARIS_PUBLIC_URL` is unset; SMTP enabled refuses the send and logs `HARIS_PUBLIC_URL`, and SMTP disabled still logs the link from the request base URL
- Fixed `excluded_paths` accepting a quantified alternation such as `(a|aa)+$`; a quantifier on a group that contains alternation or a quantifier is rejected, and the 200-character limit stays
- Fixed sandbox cleanup on exec timeout or output truncation killing only the first process group; it now kills every other process in the container, and a failed cleanup marks the sandbox unusable
- Fixed web `scanner_options` accepting a non-numeric `nuclei` `timeout` and other mistyped values; each option must be a bool, a bounded number, or a bounded string or list
- Fixed template URL downloads reading the whole response into memory; the body streams to a temporary file capped at 50 MiB over http(s) only, then replaces the target, and the temporary file is removed on failure

### Changed

- Improved test coverage for `NucleiScanner`: added 19 new tests covering `_run_phase()`, `_result_to_finding()`, `_write_url_list()`, `_generic_remediation()`, auth header forwarding, and full scan flow
- Added 5 new tests for nuclei config schema validation in `tests/test_scanner_config.py`
- Replaced the hand-rolled SQLite schema versioning with `yoyo-migrations`; a 0.6 database is backed up to `<db>.pre-0.7.bak` and adopted as the baseline, and `ScanStore` opens the database through one connection helper
- Split `ScanStore` into scan, finding, template and website repositories behind an unchanged facade
- Stored session, remember-me and email-verification tokens as SHA-256 hashes; existing rows were hashed in place so current sessions stay valid
- Risk posture weights each correlated finding by its confidence score; `RiskPosture.UNKNOWN` replaces `EXCELLENT` when no scanner completed
- Scanners after the recon stage run in parallel (default 3); remediation and risk use active (not suppressed, not refuted) correlated findings
- Duplicate findings are collapsed by fingerprint, so `finding_id` is now the first 16 characters of the fingerprint
- Moved the context extractors from `ScanEngine` to `core/context_extract.py` and the LLM stage to `core/llm_enrichment.py`
- Removed the unused `core/context.py`
- Changed LLM enrichment, attack-chain, triage, false-positive and variant output to one shared pydantic parser; a malformed item is dropped and recorded without losing the batch
- Changed LLM prompts to wrap scanner and target text in a per-call nonce `<untrusted-data>` fence, and the system prompts to state that fenced text is data
- Changed LLM calls to use provider structured output where the capability table allows it, a request timeout, jittered retries that honour `Retry-After`, and a bounded concurrency gate
- Changed LLM backends to default to the models in `llm_models.yaml`; `create_backend()` resolves the model through the provider model list when a key is set
- Changed the Ollama backend to call `/api/chat` for single and multi-turn requests
- Changed the chat retrieval threshold and prompt field limits to read from `llm_models.yaml`
- Changed every built-in check to send requests through `context.http` (`ScopedClient`); the per-check `timeout` option is replaced by `NetworkPolicy.timeout_s`
- Changed built-in findings to carry a confidence score from `confidence.yaml` (`<check>.<kind>`); a passed validator raises it
- Changed `robots.txt`, `sitemap.xml` and `security.txt` findings to INFO and moved the API-document paths from `info_disclosure` to `openapi_checks`
- Changed the agent proxy and PoC re-execution to forward `POST` only with `--agent-allow-unsafe-methods`, to the finding's own URL, for a finding observed on `POST`; `PUT`, `PATCH` and `DELETE` stay rejected
- Changed `haris bench score` to compute precision over active findings, count refuted findings and per-tier findings, and add `verified_precision`
- Updated README and docs to match the registered scanners, checks, profiles and CLI, and to quote the recorded benchmark scores with their limits
- Documented the new auth environment variables, the web scanner-option rules, the sandbox output cap, the DNS-rebinding limit and the `excluded_paths` rules

### Added

- Added `resources/config/llm_models.yaml` with default model IDs (`[UNVERIFIED]`, re-check at release), a per-model capability table, optional prices, runtime limits and the per-scan budget
- Added `resolve_model()`, which uses the provider model-list API when a key is present and the config default otherwise
- Added redaction of API keys, `Authorization` and `Cookie` values, bearer tokens, JWTs, private keys and URL credentials (emails via `redaction.emails`) before every provider call
- Added per-scan token and cost budgets; LLM stages expose `last_report` with a status per finding (`ok`, `invalid`, `failed`, `skipped_budget`)
- Added an offline LLM eval set in `tests/evals/` with prompt-injection and malformed-output cases

### Added

- Added a benchmark harness in `bench/`: loopback-only Docker Compose targets (Juice Shop, DVWA, WebGoat, an SPA catch-all fixture, a vulnerable AI app with a toy MCP server), YAML ground truth, a runner (`bench/run.py`) and a nightly `bench.yml` workflow
- Added the `haris.bench` scorer (`python -m haris.bench score <report> <ground_truth.yaml>`) reporting precision, recall, F1, false-positive reduction, request count, cost and wall time with mean and stddev over runs
- Added `docs/benchmarks.md` describing the benchmark methodology and what it does not claim
- Validated `scanner_options.extra_args` against a per-scanner allow-list in `config/scanners/*.yaml`; other flags are rejected with an error
- Placed `--` before the host argument for Nmap and SSLyze
- Passed Nmap NSE scripts through the new `nse_scripts` option instead of `extra_args`
- Switched Nuclei to `-or`, `-es info` (phases 2a and 2b), `-ept code,file,headless`, `-mhe` and `-eid http-missing-security-headers`; added the opt-in `automatic_scan` (`-as`) and `update_templates` (`-ut`) options
- Added golden fixtures from real nuclei, nikto, nmap, wapiti and sslyze output under `tests/fixtures/scanners/`
- Split `web/app.py` and `auth/router.py` into routers under `web/routers/` with a `create_app()` factory; routers are authenticated by default (`protected_router`, `admin_router`)
- Scans, websites, conversations and scan templates are visible only to their owner and admins (404 otherwise); `HARIS_SHARE_SCANS_ORG_WIDE=true` makes scans readable to all users
- Moved `GET/POST /auth/login` to `/login`; `/docs`, `/redoc` and `/openapi.json` are disabled
- Replaced Google Fonts and CDN scripts with vendored, SRI-pinned htmx 2, DOMPurify, marked and Chart.js and self-hosted Inter (`static/vendor/README`); LLM markdown is sanitised before insertion
- CSP now sets `base-uri 'none'`, `form-action 'self'`, `object-src 'none'` and `frame-ancestors 'none'`
- The Docker image runs as non-root user `haris` (uid 10001) and starts uvicorn with `--proxy-headers`; the nuclei template volume moved to `/home/haris/nuclei-templates`

### Added

- App-wide CSRF check on every `POST`, `PUT`, `PATCH` and `DELETE` (`X-CSRF-Token` header or `csrf_token` form field); the token is derived from the session cookie
- `TestClient` suites for the route matrix, ownership, CSRF, login redirects, template rendering and OIDC (`tests/test_web_*.py`, `tests/test_auth_oidc.py`)
- Migrations `0003`–`0007`: finding identity columns (`observation_id`, `fingerprint`, `vuln_class`, `confidence_score`, `verification_json`, `suppression_json`), scan owner and state columns, and the `api_tokens`, `authorized_targets` and `jobs` tables; every step has a rollback
- Persisted scans reload with fingerprint, observation id, confidence, verification, suppression, correlated findings, scan state and scanner status; 0.6 rows get their identity recomputed on read
- Scan and template ownership are columns (`scans.owner_user_id`, backfilled from `started_by`, and `scan_config_templates.owner_user_id`); list, dashboard and trend queries filter by owner in SQL
- Web scans need an authorised target: the host must pass the SSRF guard (400 otherwise) and match `HARIS_TARGET_ALLOWLIST` or hold a proof verified in the last 30 days (403 otherwise)
- Proof of ownership per (user, host): `haris-verify=<32 hex>` in a DNS TXT record at `<host>` or `_haris-verify.<host>`, or in `/.well-known/haris-verify.txt`, fetched without redirects
- `POST/GET /api/v1/targets`, `POST /api/v1/targets/{host}/verify` and `DELETE /api/v1/targets/{host}` manage proofs
- API tokens (`haris_pat_…`, SHA-256 at rest, scopes `scans:read`, `scans:write`, `targets:write`, `admin`, 90-day default and 365-day maximum expiry, revocable) via `/api/v1/tokens`; accepted only as `Authorization: Bearer` on `/api/v1/*` and exempt from CSRF
- DB-backed scan queue with persisted `queued`, `running`, `completed`, `failed`, `cancelled` and `incomplete` states, cancellation (`POST /api/v1/scans/{id}/cancel`), restart recovery and `HARIS_MAX_CONCURRENT_SCANS` (default 2)
- `GET /api/v1/llm/conversations` and `GET /api/v1/admin/users`
- `haris --web --proxy-headers`

### Changed

- JSON endpoints moved from `/api/*` to `/api/v1/*` with declared response models; the old paths return 404. Migration: `/api/scan/start` is `POST /api/v1/scans`, `/api/scan/{id}/status` is `GET /api/v1/scans/{id}`, `/api/scan/{id}/report/{fmt}` is `GET /api/v1/scans/{id}/report.{fmt}`, `/api/scan/{id}/findings|enrichment` sit under `/api/v1/scans/{id}/`, `/api/website/{host}/…` is `/api/v1/websites/{host}/…`, and the LLM routes are `/api/v1/llm/{ask,chat,summarize,explain,remediation-plan,test-cases,mitigations,filter-findings}` with `scan_id` in the JSON body
- `DELETE /api/v1/scans/{id}` returns 204 and 409 while the scan is queued or running
- LLM routes return 429 when the budget is exhausted and a generic message for other failures; exception text is logged, not returned
- Scans survive a server restart as `incomplete`; target credentials are held in memory only and never stored with the job
- `haris --web` builds the app with `create_app()`; the compose healthcheck calls `/health`

### Removed

- `web/ownership.py` (`ResourceOwners`) and `web/scoped_views.py`, replaced by owner-aware queries
- Removed the unused `haris.ai_security.jsonrpc` module

## 0.6.2 — 2026-04-04

### Fixed

- Downgraded python versions to fix pydantic incompatability issue
- Fixed mypy errors by installing `web` extra so mypy can resovle FastAPI/authlib imports
- Upgraded vulnerable pygments to 2.20.0 (CVE-2026-4539)
- Suppressed known vulnerabilities in wapiti3 transitive dependencies (flask, pyopenssl, tornado) in pip-audit; upstream wapiti3 does not support patched versions

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
