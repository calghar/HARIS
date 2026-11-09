## Context

HARIS 0.6.2 runs external scanners and built-in checks sequentially (`ScanEngine.run`), merges raw findings by `(title, url, parameter)`, correlates them with a SHA-256 key over `hostname|path|parameter|tags[0]|method` that mutates the shared canonical `Finding` to `CONFIRMED`, and scores risk over the uncorrelated `all_findings` with static confidence. `finding_id` is a random 12-hex UUID, so no diff or baseline exists. Built-in checks call `requests` directly; `Scope.rate_limit_rps` and `max_requests` are never enforced; `misc_checks._check_sensitive_paths` flags any HTTP 200. The web layer (`web/app.py:494-600`) accepts any `target_url`, applies no SSRF guard, ownership or target authorisation, and stores session tokens in plaintext. The LLM false-positive step (`llm/correlation.py`) reads short evidence excerpts, never replays a request, and its verdicts are unvalidated.

Stable boundaries:
- JSON report: existing keys stay; new keys are additive (`fingerprint`, `confidence_score`, `verification`, `suppression`, `scan_state`).
- SQLite: migrated in place; no data loss.
- `BaseScanner`, `@register_scanner`, `@register_check` keep their signatures; `scan()` gains access to a `ScopedClient` through `ScanContext`.
- `config/*.yaml` keys keep their meaning; new keys are additive.
- External tools run via argv lists only; target content never reaches argv except the validated target URL.

Do not touch: external tool CLIs; `config/scanner_data.yaml` semantics except where a task names it.

## Goals / Non-Goals

**Goals:**
- Stable finding identity enabling correlation, baseline, ignore and diff.
- Every finding carries a verification tier and numeric confidence; risk weights both; nothing is silently dropped.
- One outbound HTTP choke point that enforces scope, SSRF guard, rate limit, request cap and per-hop redirect checks.
- Soft-404/SPA baseline eliminating path false positives on catch-all sites.
- Verification stage: deterministic replay, LLM case verdict, opt-in sandboxed agentic validator.
- AI-system security module with OWASP LLM, Agentic and MCP mappings.
- Web access control: authentication, ownership, CSRF, target authorisation, API tokens.

**Non-Goals:**
- Browser-based crawling or authenticated login flows (later release).
- Destructive exploitation, persistence, lateral movement or any write to target data.
- Generating harmful content in AI probes.
- Multi-tenant organisations beyond owner/admin visibility.
- Rewriting external tools' traffic engines.

## Decisions

### D1. Finding schema and identity (`src/haris/models/finding.py`, `src/haris/core/identity.py`, `src/haris/core/vuln_class.py`)

Canonical class:
- `VulnClass` is a string id from `config/vuln_classes.yaml`: each entry has `id` (e.g. `xss_reflected`, `sqli_error`, `sqli_time`, `missing_header`, `insecure_cookie`, `sensitive_file`, `tls_weak_protocol`), `primary_cwe` (e.g. `CWE-79`), `granularity` (`host` | `path` | `parameter`) and `aliases` keyed by scanner (`wapiti: [...]`, `nuclei: [...]`, `nikto: [...]`, `builtin: [...]`).
- Unmapped findings get `unclassified:<scanner>:<slug(title)>`, so they never merge across scanners by accident.
- Header and cookie findings put the header or cookie name in `parameter`.

Fingerprint (`identity.fingerprint(finding, base_url) -> str`):
- Inputs, in order: schema version `v1`; CWE (the class `primary_cwe` when mapped, else the finding's `cwe_id` normalised to `CWE-<n>`, else `CWE-NONE`); `vuln_class`; normalised URL; method upper-cased; parameter.
- URL normalisation: resolve relative URLs against `Target.base_url`; lower-case scheme and host; IDNA-encode host; drop default ports (80/443); drop fragment; collapse duplicate slashes; strip trailing `/` (root stays `/`); percent-decode unreserved characters; keep query parameter names sorted and de-duplicated, drop all values.
- Granularity: `host` keeps scheme+host+port only, clears method and parameter; `path` clears parameter; `parameter` keeps all.
- Hash: SHA-256 over the inputs joined by `\x1f`, hex-encoded (64 chars) → `fingerprint`.
- `finding_id = fingerprint[:16]`. The former random id moves to `observation_id` (uuid4 hex, 12 chars); `CorrelatedFinding.sources` becomes `list[tuple[scanner, observation_id]]`.

Confidence:
- `confidence_score: float` in `[0.0, 1.0]`. `confidence` (enum, unchanged values) is derived: `>= 0.9` → `confirmed`, `>= 0.6` → `firm`, else `tentative`.
- Priors per source in `config/confidence.yaml` (per built-in check id, per external scanner, per Nuclei severity is NOT used). Default prior when absent: `0.5`.

Verification object (`Verification`, always present, default tier `unverified`):
- `tier`: `unverified` | `replay_verified` | `exploit_validated` | `refuted`.
- `method`: `none` | `replay` | `agent`.
- `oracle`: `none` | `reflection` | `error_signature` | `timing` | `header_presence` | `content_validator` | `soft404` | `canary`.
- `baseline_ref`: request-log id of the control or baseline response, empty when none.
- `evidence`: list of `EvidenceExchange` {`request_id`, `role` (`probe` | `control` | `baseline` | `poc`), `method`, `url`, `request_headers` (redacted), `request_body_excerpt`, `status`, `response_headers` (redacted), `response_body_excerpt` (≤ 8 KiB), `elapsed_ms`}.
- `verdict_source`: `deterministic` | `llm:<model_id>` | `agent:<model_id>`.
- `llm`: optional `LLMAssessment` {`verdict`, `confidence`, `cited_spans`, `model`, `rationale`, `status` (`ok` | `abstained` | `invalid` | `skipped_budget`)}.
- `timestamp`: ISO-8601 UTC of the last tier change.

Tier transitions (only these):
- `unverified → replay_verified`: positive deterministic oracle.
- `unverified → refuted`: deterministic negative oracle with refutation semantics (`soft404` match, `content_validator` fail, `header_presence` shows the header present).
- `unverified | replay_verified → exploit_validated`: agent PoC re-executed deterministically by the validator with a positive oracle.
- LLM verdicts never change the tier.

Correlation (`src/haris/core/correlator.py`):
- Buckets by `fingerprint`. Canonical = `model_copy(deep=True)` of the member with highest tier rank (`exploit_validated` > `replay_verified` > `unverified` > `refuted`), then severity, then `confidence_score`. Input findings are never mutated.
- Consensus: `confidence_score = min(0.95, 1 - Π(1 - c_i))` over the maximum prior per distinct scanner; then tier floor: `replay_verified` → `max(score, 0.9)`, `exploit_validated` → `1.0`, `refuted` → `0.0`.
- LLM adjustment after consensus: `confirmed` → `+0.15 × llm_confidence` capped at `0.89`; `likely_fp` → `−0.3 × llm_confidence` floored at `0.05`; tier floors win.
- The severity of the correlated finding is the maximum severity in the bucket.

Risk (`src/haris/core/risk.py`):
- Reads `session.correlated`. Excludes tier `refuted` and suppressed findings.
- `score = Σ weight(severity) × confidence_score`, weights unchanged (25/10/3/1/0). Thresholds: `>= 50` critical, `>= 25` poor, `>= 10` moderate, `> 0` good, `0` excellent.
- New `RiskPosture.UNKNOWN` when no scanner completed.

Never silently drop: `refuted` and suppressed findings stay in JSON, SARIF (with `suppressions`/`baselineState`) and an appendix section; default report sections, risk and `--fail-on` exclude them.

### D2. Scoped HTTP client (`src/haris/net/scoped_client.py`, `src/haris/net/ssrf.py`, `src/haris/net/ratelimit.py`)

`ScopedClient(target, policy: NetworkPolicy, log: RequestLog)`; one instance per scan, shared by every built-in check, the baseline module and the replay verifier. Built-in checks MUST NOT import `requests` directly (ruff `flake8-tidy-imports` banned-api rule enforces it outside `haris.net`).

Per request (and per redirect hop):
1. Scheme in {`http`, `https`}; else `ScopeViolation`.
2. `Scope.is_url_in_scope(url)` and method in `Scope.allowed_methods`; else `ScopeViolation`.
3. SSRF guard: resolve host with `getaddrinfo` once per (host, port) per scan and cache; reject if ANY resolved address is blocked; connect to the first vetted address with `Host` header and TLS SNI/cert hostname set to the original host (pinned `HTTPAdapter`).
4. Token bucket: capacity `max(1, ceil(rate_limit_rps))`, refill `rate_limit_rps`; blocking acquire.
5. Request counter: the request that would exceed `Scope.max_requests` raises `RequestBudgetExceeded`; the caller records a scan error and stops issuing requests.
6. Send with `allow_redirects=False`. If `Scope.follow_redirects`, follow `Location` up to `Scope.max_redirect_depth` hops, repeating steps 1-5 on each hop; a hop that fails any step ends the chain and returns the last in-scope response with `redirect_blocked` set.
7. Retries: up to 2 on connection errors and 502/503/504 with exponential backoff `0.5 s × 2^n` plus jitter. 429: honour `Retry-After` capped at 60 s, halve the bucket refill rate for the rest of the scan, at most 3 attempts.
8. Log: `RequestLog` entry (`request_id`, redacted request/response, excerpt ≤ 8 KiB, timing). Redacted headers: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and any name matching `(?i)(token|secret|api[-_]?key|auth|session)`. Ring buffer default 5000 entries per scan.

Blocked address classes (`ssrf.is_blocked(ip)`): unspecified (`0.0.0.0/8`, `::`), loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT `100.64.0.0/10`, link-local (`169.254/16`, `fe80::/10`), ULA `fc00::/7`, multicast, reserved, benchmarking `198.18.0.0/15`, IETF `192.0.0.0/24`, documentation ranges, and IPv4 embedded in IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96` and 6to4 `2002::/16` (checked as the embedded IPv4). Metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, host `metadata.google.internal`) is always blocked, even with the override.

Override: `NetworkPolicy.allow_private: bool = False`. CLI enables it with `--allow-private`. The web UI never sets it from a request; only the server env `HARIS_ALLOW_PRIVATE_TARGETS=true` enables it for all web scans.

External tools (no in-process choke point):
- Pre-flight: the target host passes steps 1-3 before any tool starts; the resolved IP is passed where the tool accepts it (`nmap` scans the vetted IP).
- Rate: concurrent tools share `rate_limit_rps`; each gets `rate_limit_rps / n_concurrent` (min 1). Flags: nuclei `-rl <n> -c <n>`, nmap `--max-rate <n>`, nikto `-Pause <s>`; wapiti has no per-second limit flag [UNVERIFIED against 3.2.10 `--help`], so it is bounded by `--max-scan-time` and its own concurrency setting `--tasks 1`[UNVERIFIED]. Each flag is confirmed against the tool's `--help` at implementation time.
- `max_requests` is enforced exactly only for in-process traffic; per-tool request caps are documented as best-effort.

### D3. Soft-404 / SPA baseline (`src/haris/checks/baseline.py`, `src/haris/checks/validators.py`)

`ResponseFingerprint` = (`status`, `content_type` media type lower-cased without parameters, `length_bucket` = `len(body) // 512`, `body_hash`, `title`).
- `body_hash`: SHA-256 of the body after removing the requested path (raw and percent-encoded), removing digit runs of 4+ and `[A-Za-z0-9+/=_-]{16,}` tokens, collapsing whitespace.
- `title`: `<title>` text, whitespace-collapsed, lower-cased; empty when absent.

Controls per host (cached for the scan, sent through `ScopedClient`): `/<r>`, `/<r>/`, `/<r>.html` where `<r>` = `haris-` + 16 random hex; plus lazily `/<dir>/<r>.<ext>` for each probed (directory, extension) pair, at most 10 extra per host.

Similarity rule: response R matches control C when `R.status == C.status` AND `R.content_type == C.content_type` AND (`R.body_hash == C.body_hash` OR (`R.title == C.title` AND `|len(R) − len(C)| <= max(64, 0.05 × len(C))`)). For 3xx: match when both redirect to the same normalised `Location` (random path segment removed).

Host classes: `catch_all` when ≥ 2 controls return 2xx; `unstable` when controls disagree with each other; `normal` otherwise.

Decision for a path probe returning 2xx:
- Matches any control → no finding (logged at debug).
- Path has a validator → finding only if the validator passes.
- No validator and host `catch_all` or `unstable` → no finding.
- No validator and host `normal` → finding with prior `0.5`.

`ContentValidator` protocol: `name: str`; `validate(resp: ScopedResponse) -> ValidatorResult(passed: bool, reason: str, span: str)`. Registry in `validators.py`:
- `/.env`: ≥ 2 lines matching `^[A-Z_][A-Z0-9_]*=`; body does not start with `<`.
- `/.git/config`: contains `[core]` and `repositoryformatversion`.
- `/.git/HEAD`: matches `^ref: refs/`.
- `/server-status`: contains `Apache Server Status`.
- `/phpinfo.php`: contains `PHP Version` and `phpinfo()`.
- `/.DS_Store`: body starts with bytes `00 00 00 01 42 75 64 31`.
- `/openapi.json`, `/swagger.json`: JSON object with key `openapi` or `swagger`.
- `/actuator/env`: JSON object with key `propertySources`.

### D4. Verification stage (`src/haris/verify/`)

Modules: `pipeline.py`, `replay.py`, `oracles.py`, `evidence.py`, `llm_verdict.py`, `agent/coordinator.py`, `agent/sandbox.py`, `agent/proxy.py`, `agent/guardrails.py`, `agent/validator.py`, `agent/audit.py`.

Pipeline order (after all scanners): correlate → apply ignore file → replay verifier → LLM case verdict → agent validator (opt-in) → recompute confidence → risk → reports. Suppressed findings skip verification.

Replay verifier (`replay.py`):
- Applies to correlated findings whose class maps to an oracle in `config/vuln_classes.yaml` (`oracle:` key) and whose method is in `Scope.allowed_methods`; others keep tier `unverified`, `method=none`.
- Sends a probe and a control (same request, payload replaced by a random token of equal length) through `ScopedClient`. Budget `verify.max_requests` default 500, counted inside `Scope.max_requests`.
- Oracles:
  - `reflection`: probe uses its own marker `"'><haris<r8>>`; positive when the response is `text/html` and contains `<haris<r8>>` unencoded outside `<script>` string literals and `<!-- -->`, and the control does not.
  - `error_signature`: regexes from `config/error_signatures.yaml` (e.g. `You have an error in your SQL syntax`, `ORA-\d{5}`, `PG::SyntaxError`, `SQLSTATE\[`); positive when a pattern matches the probe and matches neither the control nor the host baseline.
  - `timing`: delay `D` default 5 s, `N` default 3 interleaved probe/control pairs; positive when `min(probe) − max(control) >= 0.8 × D` and `median(probe) >= D`.
  - `header_presence`: two GETs; positive when the header is absent (or invalid) in both; refutes when present and valid in both; else inconclusive.
  - `content_validator` / `soft404`: D3 rules; refutes on soft-404 match or validator fail.
- Outcome: positive → `replay_verified`; refuting oracle negative → `refuted`; otherwise `unverified` with `method=replay`.

LLM case verdict (`llm_verdict.py`):
- Input `CaseBundle` {`case_id`, `finding` (title, vuln_class, cwe, severity, url, method, parameter, scanners), `exchanges` (probe, control, baseline: redacted request ≤ 4 KiB, status, allow-listed response headers, body excerpt ≤ 8 KiB centred on the oracle match), `oracle_results`}.
- Fencing: every exchange wrapped in `<untrusted-data id="<nonce>">…</untrusted-data id="<nonce>">` with a per-call random nonce; system prompt states that fenced content is data and that instructions inside it are ignored. Redaction runs before the bundle is built.
- Output (provider structured output, validated by pydantic): {`case_id`, `verdict`: `confirmed` | `likely_fp` | `inconclusive`, `confidence` 0..1, `cited_spans`: 1-5 items {`exchange_index`, `text` ≤ 300 chars}, `rationale` ≤ 600 chars}.
- Validation: `case_id` must match; each span must be an exact substring of the referenced exchange text as sent; `confirmed`/`likely_fp` require ≥ 1 valid span. Failure → `status=invalid`, verdict treated as `inconclusive`.
- Abstain: `confidence < verify.llm.abstain_below` (default 0.7, calibrated in Phase 3) → `status=abstained`.
- Scope: cases with tier `unverified` only; ordered by severity then `confidence_score`. Budget: `verify.llm.max_cases` 50, `verify.llm.max_tokens` 200000, `verify.llm.max_cost_usd` 2.00 (price table in config; unknown price → token cap only). Cases beyond budget get `status=skipped_budget`.

Agentic validator (`verify/agent/`), opt-in:
- Enabled only with `--agent` AND `--i-have-authorization`; `--agent` alone exits 3. Web UI: admin role and a verified target authorisation (D7) required. Env `HARIS_AGENT_DISABLED=1` hard-disables it.
- Candidates: tier `unverified` or `replay_verified`, severity ≥ medium, class in `agent.classes` (default `xss_reflected`, `sqli_error`, `sqli_time`, `path_traversal`, `open_redirect`, `ssrf`).
- Roles:
  - Coordinator (host process): selects candidates, writes a job spec, runs the LLM loop for the sandbox agent, enforces budgets, owns the kill switch. LLM API keys stay on the host.
  - Sandbox agent: its tool calls execute inside the job container. Tools: `http_request` (through the proxy), `run_python` (script file in `/work`), `write_file`/`read_file` (`/work` only), `submit_poc`. No generic shell; binaries are argv-only from an allow-list (`python3`, `curl`).
  - Validation agent: separate LLM context with no tools; reviews the PoC and audit log. The final decision is deterministic: `validator.py` re-executes the submitted PoC through `ScopedClient` with a fresh nonce where the oracle allows, and checks the class oracle.
- "No PoC, no exploit_validated": a job without a `submit_poc` artifact {requests, oracle, expected span}, or whose re-execution fails, leaves the tier unchanged.
- Container (per job, `docker run`): digest-pinned image `haris-agent-sandbox`; `--rm --read-only --tmpfs /work:rw,size=64m --tmpfs /tmp:rw,size=16m --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 512m --cpus 1 --user 65534:65534`; default seccomp; no volumes, no Docker socket, no host network; env only `HTTP_PROXY`/`HTTPS_PROXY` and the job CA path.
- Network: job network created with `--internal`; its only peer is the proxy sidecar `haris-scope-proxy`, which also joins an egress network. The proxy terminates TLS with an ephemeral per-job CA trusted only inside the sandbox, enforces scope, SSRF guard, method allow-list, rate (default 2 rps per job) and request cap (default 300 per job), and logs every exchange to the audit log.
- Budgets (defaults, configurable): `agent.max_tool_calls` 40, `agent.max_tokens` 300000 per job, `agent.wall_clock_s` 600 per job, `agent.max_jobs` 10 per scan, `agent.max_cost_usd` 10.00 per scan.
- Kill switch: any budget breach, 3 guardrail hits in one job, `haris cancel <scan>`, SIGINT or web cancel → `docker kill` on the job container and proxy, job marked `aborted`, tier unchanged.
- Audit log: append-only JSONL `<out>/agent/<job_id>/audit.jsonl` (LLM message digests, tool calls with args, tool result digests, proxy exchanges, guardrail hits, budget counters); stored with the scan.
- Guardrails (`guardrails.py`), motivated by [CAI: Hacking the AI Hackers via Prompt Injection](https://arxiv.org/html/2508.21669), where injected tool output carried encoded payloads the agent decoded and executed:
  - Tool output returned to the LLM is fenced as untrusted data (nonce fence as in LLM verdict) and scanned for instruction-like patterns; hits are annotated, not removed.
  - Tool-call arguments are rejected when they contain shell substitution (`$(`, backticks, `${`), pipes into interpreters (`| sh`, `| bash`, `| python`), `eval`/`exec(`, `base64 -d`/`--decode`/`b64decode`/`fromhex` combined with execution, or `curl … | …`.
  - `run_python` scripts are statically checked with `ast`: no `subprocess`, `os.system`, `os.exec*`, `socket` outside `requests`/`urllib`, `exec`, `eval`, `compile`, `__import__`.
- Non-destructive PoCs: methods `GET`, `HEAD`, `OPTIONS` by default; `POST` only if the class requires it and `--agent-allow-unsafe-methods` is set; `PUT`, `PATCH`, `DELETE` never. The proxy rejects bodies or queries containing `DROP`, `DELETE FROM`, `UPDATE … SET`, `INSERT INTO`, `TRUNCATE`, `ALTER`, `SHUTDOWN`, `xp_cmdshell`, stacked queries (`;` followed by a SQL keyword), and sleep values > 10 s.

Threat model (attacks on the agent):
- Prompt injection from target responses → nonce fencing, guardrail scan, no secrets in the sandbox, tool-argument filter, deterministic re-execution decides the tier.
- SSRF via the agent → internal-only network, proxy scope + SSRF guard with pinned resolution, metadata always blocked.
- Sandbox escape → non-root, read-only rootfs, all capabilities dropped, no-new-privileges, seccomp, no socket or host mounts, pids/memory/CPU limits; rootless Docker recommended in docs.
- Cost exhaustion (looping or injected "keep trying") → tool-call, token, wall-clock and cost caps per job and per scan, kill switch.
- Forged success evidence (target echoes a fake marker) → validator uses a fresh nonce chosen after PoC submission.
- Data exfiltration → egress only to in-scope hosts; LLM keys never enter the container.

Untrusted target content: sinks and treatment:
- JSON report and SARIF: JSON-escaped strings, excerpts capped at 8 KiB.
- HTML report and dashboard: Jinja autoescape, no `|safe` on target or LLM text; LLM Markdown rendered client-side through DOMPurify.
- Markdown report: target text inside fenced code blocks with the fence length chosen longer than any backtick run in the text.
- LLM prompts and agent tool output: redaction then nonce fence.
- Logs: control characters stripped, 500-char cap.
- External tool argv: only the validated target URL; never response content.

### D5. Engine pipeline (`src/haris/core/engine.py`)

- Stages: `recon` (sequential: built-in header/misc/info checks, nmap; writes `ScanContext`) → `scan` (parallel, `ThreadPoolExecutor(max_workers=--parallel, default 3)`; `ScanContext` read-only) → `verify` (D4) → `report`.
- Per-tool rate budget: D2 split of `rate_limit_rps` across concurrently running tools.
- Partial persistence: after each scanner returns (including timeout with partial output), its `ScannerResult` is written to the DB and to `<out>/session.partial.json`.
- `ScanSession.scan_state`: `pending` | `running` | `completed` | `incomplete` (≥ 1 scanner errored or timed out, ≥ 1 completed) | `failed` (none completed) | `cancelled`.
- Exit codes: `0` completed and no finding at or above `--fail-on`; `1` ≥ 1 correlated, non-refuted, non-suppressed finding with severity ≥ `--fail-on`; `2` state `incomplete`, `failed` or `cancelled`; `3` usage or config error (bad flags, invalid ignore file, missing `--i-have-authorization`). Precedence `3 > 2 > 1 > 0`. Without `--fail-on`, code 1 is never returned.
- Ignore file `.haris-ignore.yaml` (path override `--ignore-file`):

```yaml
version: 1
ignores:
  - fingerprint: "<64 hex>"        # exactly one of fingerprint | rule
    reason: "Accepted risk, ticket SEC-12"
    expires: 2027-03-31
    author: alice@example.com
  - rule: missing_header           # vuln_class id
    url: "https://example.com/static/**"   # glob on normalised URL, optional
    reason: "Static CDN"
    expires: 2027-01-31
    author: bob@example.com
```

  `reason`, `expires` (ISO date) and `author` are required. Expired entries suppress nothing and emit a warning. Matching findings get `suppression` {`source: ignore_file`, `reason`, `author`, `expires`}.
- Scan diff (`haris diff <old.json> <new.json>` and `--baseline <old.json>` on `scan`): keyed by `finding_id`; `new` (only in new), `fixed` (only in old, and the old finding's scanner completed in the new scan), `not_retested` (only in old, scanner did not complete), `unchanged` (both). Refuted findings are compared like any other but reported in their own column.

### D6. AI-system security module (`src/haris/ai_security/`, `src/haris/scanners/garak_scanner.py`, `src/haris/scanners/promptfoo_scanner.py`)

Modules: `discovery.py`, `signatures.py`, `passive.py`, `mcp_probe.py`, `mcp_static.py`, `active.py`, `canary.py`, `owasp_ai.py`. All traffic through `ScopedClient`; discovery reuses the D3 baseline, so a catch-all host cannot produce discovery hits without a body-validator pass.

Discovery signatures (method, path, body validator):
- OpenAI-compatible: `GET /v1/models` → JSON `object == "list"` and `data[*].id`; `POST /v1/chat/completions` only under `--ai-active`.
- Ollama: `GET /api/tags` → JSON key `models` (list); `GET /api/version` → key `version`.
- vLLM: `GET /v1/models` with `data[*].owned_by == "vllm"`; `GET /version` → key `version`.
- TGI: `GET /info` → keys `model_id` and `max_input_tokens` or `max_total_tokens`.
- Triton: `GET /v2` → keys `name` and `extensions`; `GET /v2/health/ready` → 200.
- LangServe: `GET /docs` contains `LangServe` or `GET /<path>/input_schema` → JSON schema object.
- Flowise: `GET /api/v1/chatflows` → JSON list of objects with `flowData`, or 401 JSON from Flowise.
- Open WebUI: `GET /api/config` → keys `name` containing `Open WebUI` and `features`.
- Gradio: `GET /config` → keys `version` and `components`.
- MLflow: `GET /api/2.0/mlflow/experiments/search?max_results=1` → key `experiments`, or page title `MLflow`.
- Ray: `GET /api/version` → key `ray_version`; dashboard title `Ray Dashboard`.
- ComfyUI: `GET /system_stats` → keys `system` and `devices`.
- Jupyter: `GET /api` → key `version`; `GET /api/kernels` 200 JSON list → unauthenticated.
- MCP Streamable HTTP: `POST /mcp` JSON-RPC `initialize` → JSON-RPC result with `protocolVersion` and `serverInfo` (read-only probe, passive tier).
- MCP SSE: `GET /sse` → `Content-Type: text/event-stream` and an `endpoint` event.
- OAuth protected resource: `GET /.well-known/oauth-protected-resource` → JSON with `resource` and `authorization_servers`.
- Chat widgets: script URLs or bundle text matching known widget loaders in `config/ai_signatures.yaml`.

Passive checks: unauthenticated inference or admin endpoints; provider keys in client bundles (`sk-`, `sk-ant-`, `AIza`, `hf_` patterns with entropy check); system prompts or model config in bundles; verbose provider errors; CORS `*` or reflected origin with credentials on chat APIs; missing rate limiting via a capped burst (≤ 10 requests at the scan rate, `--ai-active` only); missing `max_tokens` caps (`--ai-active` only); MCP over plaintext `http` from a non-loopback host.

MCP read-only probe: `initialize` then `tools/list` (and `resources/list`, `prompts/list` when advertised). Never `tools/call`. Static tool-definition heuristics (`mcp_static.py`): instruction-like text in descriptions (`ignore previous`, `do not tell the user`, `<IMPORTANT>`); hidden Unicode (tags block U+E0000-U+E007F, zero-width U+200B-U+200D, U+2060, bidi controls U+202A-U+202E, U+2066-U+2069); excessive-agency schemas (free-form `command`, `code`, `sql`, `path`, `url` string parameters without `enum`/`pattern`); toxic flows (a server exposing both a private-data read tool and an external-send tool); tool names shadowing common tools.

Active probes (`--ai-active`, requires target authorisation like D7; CLI requires `--i-have-authorization`): canary-token prompt injection (`HARIS-CANARY-<r16>` must appear only if the injected instruction was followed), system-prompt leakage (bench fixtures plant a canary; live targets: verdict only on known prefix markers supplied by the user via `--ai-system-prompt-marker`), output-handling XSS with an inert marker `<haris-x<r8>>` checked for raw reflection in HTML sinks, a curated jailbreak set limited to canary-elicitation goals. Verdicts are string matches on canaries; no LLM judge.

Adapters (`BaseScanner` subclasses):
- garak: generate a REST generator JSON config from the discovered endpoint (URI, headers with auth redacted in logs, `req_template_json_object`, `response_json_field`), run `garak --model_type rest -G <cfg> --probes <list> --report_prefix <tmp>`; parse the `.report.jsonl` `eval` entries; finding per probe/detector with fail rate `r = fails / total`; `confidence_score = min(0.95, 0.5 + 0.5 × r)`; omit `r == 0`. Exact flag names verified against the installed garak `--help` at implementation time.
- promptfoo: generate `promptfooconfig.yaml` with an `http` provider for the endpoint and the chosen red-team plugins; run `promptfoo redteam run -c <cfg> -o <out.json>` (or `promptfoo eval`); parse `results.results[*]` with `success == false` into findings; confidence from per-plugin fail rate as for garak. Flags verified at implementation time.
- Licence of each tool checked before documenting redistribution; both are external CLIs, not vendored.

OWASP Top 10 for LLM Applications 2026 (verified at genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ and the GenAI-LLM-Top10 repository, published 2026-08-04):
- LLM01:2026 Prompt Injection
- LLM02:2026 Sensitive Information Disclosure
- LLM03:2026 Excessive Agency
- LLM04:2026 Supply Chain
- LLM05:2026 Data and Model Poisoning
- LLM06:2026 Unbounded Consumption
- LLM07:2026 Misinformation
- LLM08:2026 Hidden Context Exposure (replaces System Prompt Leakage)
- LLM09:2026 Vector and Embedding Weaknesses
- LLM10:2026 Improper Output Handling

OWASP Top 10 for Agentic Applications 2026 (verified at genai.owasp.org, document version 2026, December 2025):
- ASI01 Agent Goal Hijack
- ASI02 Tool Misuse and Exploitation
- ASI03 Identity and Privilege Abuse
- ASI04 Agentic Supply Chain Vulnerabilities
- ASI05 Unexpected Code Execution (RCE)
- ASI06 Memory & Context Poisoning
- ASI07 Insecure Inter-Agent Communication
- ASI08 Cascading Failures
- ASI09 Human-Agent Trust Exploitation
- ASI10 Rogue Agents

OWASP MCP Top 10 (verified at owasp.org/projects/mcp-top-10 and github.com/OWASP/www-project-mcp-top-10, version 2025; hosted by OWASP, not genai.owasp.org; project maturity [UNVERIFIED]):
- MCP01:2025 Token Mismanagement & Secret Exposure
- MCP02:2025 Privilege Escalation via Scope Creep
- MCP03:2025 Tool Poisoning
- MCP04:2025 Software Supply Chain Attacks & Dependency Tampering
- MCP05:2025 Command Injection & Execution
- MCP06:2025 Prompt Injection via Contextual Payloads
- MCP07:2025 Insufficient Authentication & Authorization
- MCP08:2025 Lack of Audit and Telemetry
- MCP09:2025 Shadow MCP Servers
- MCP10:2025 Context Injection & Over-Sharing

Check → category mapping (`owasp_ai.py`; a finding may carry several):
- Unauthenticated inference endpoint → LLM06, ASI03; for MCP → MCP07.
- Provider key in bundle → LLM02; MCP token in bundle → MCP01.
- System prompt or model config in bundle, or leakage probe hit → LLM08.
- Verbose provider error → LLM02.
- CORS on chat API → LLM02 plus web A01/A02 as today.
- Missing rate limit / max_tokens cap → LLM06.
- Prompt-injection canary followed → LLM01; through tool or retrieved content → ASI01.
- Output-handling XSS → LLM10 (+ CWE-79).
- MCP instruction text or hidden Unicode in tool definitions → MCP03, MCP06, ASI04.
- MCP excessive-agency schema → LLM03, MCP02, ASI02; free-form command/code parameter → MCP05, ASI05.
- MCP toxic flow → ASI02, MCP10.
- Unauthenticated `initialize`/`tools/list` → MCP07, MCP09.
- Plaintext MCP SSE → MCP07 (+ CWE-319).
- garak/promptfoo results: per-probe/plugin mapping table in `config/ai_mappings.yaml`.

Safety:
- Passive and read-only MCP probes run with discovery; anything that sends prompts runs only with `--ai-active` and target authorisation.
- Probes elicit canary strings only; no prompts request harmful content; the jailbreak set is reviewed into the repo, not fetched at runtime.
- Probe traffic uses the scan rate limit with an AI-specific cap `ai.max_prompts` default 50 and `ai.max_tokens_per_prompt` 256 to bound target cost.
- garak/promptfoo runs require `--ai-active`; their probe lists default to injection/leakage families.

### D7. Web access control (`src/haris/web/routers/`, `src/haris/auth/`)

- Routers: `pages`, `scans`, `llm`, `templates`, `admin`, `auth`, `targets`, `tokens`, all JSON routers under `/api/v1`; legacy `/api/*` paths are removed (404), templates updated in the same task. Each router declares `dependencies=[Depends(require_user)]` (admin router: `require_admin`); only `auth` login/callback, `/health` and `/static` are public. A test enumerates `app.routes` and fails on any non-allow-listed route without the dependency.
- Unauthenticated: `/api/v1/*` → 401 JSON; HTML pages → 303 to `/login?next=<path>`; `next` accepted only when it starts with `/`, not `//` or `/\`, and has no scheme or host; else `/`.
- Ownership: `scans.owner_user_id` (backfilled from `started_by`). Visible to owner and `admin`. Others get 404. `HARIS_SHARE_SCANS_ORG_WIDE=false` default; when true every authenticated user may read all scans; non-owner deletes get 403. LLM ask/chat/conversation routes enforce ownership of the referenced scan.
- CSRF: app-wide middleware; every `POST`/`PUT`/`PATCH`/`DELETE` authenticated by session cookie requires header `X-CSRF-Token` (HTMX) or form field `csrf_token` equal to the per-session token (synchronizer pattern, constant-time compare) → else 403. Requests authenticated by Bearer API token are exempt. Session cookie `SameSite=Lax`, `HttpOnly`, `Secure` when HTTPS.
- Target authorisation (web scans): host must be in `HARIS_TARGET_ALLOWLIST` (comma-separated host globs) or have an `authorized_targets` row for the starting user with `verified_at` within 30 days. Proof: token `haris-verify=<32 hex>` issued per (user, host); verified by DNS TXT on `<host>` or `_haris-verify.<host>`, or by `GET https://<host>/.well-known/haris-verify.txt` (then `http://` if HTTPS fails) through `ScopedClient` with redirects disabled, body stripped equal to the token. Proof covers the exact host only. SSRF guard runs before proof and before scan start.
- API tokens: format `haris_pat_<43 url-safe base64 chars>` (32 random bytes); stored as SHA-256 hex with `token_prefix` (first 12 chars) for display; scopes `scans:read`, `scans:write`, `targets:write`, `admin`; `expires_at` required, default 90 days, max 365; `last_used_at`; revocable. Accepted only on `/api/v1/*` via `Authorization: Bearer`.
- Session tokens: stored as SHA-256 hex of the raw token (raw token is 32 random bytes; slow hashing not needed); lookup by hash.
- `scanner_options.extra_args` validated against a per-scanner allow-list (WS-C).

### D8. Package and DB migration

- Package: `src/` → `src/haris/` (import `haris.*`), CLI entry `haris = "haris.cli:main"`, `__version__` from `importlib.metadata.version("haris")`, `scripts` package removed. No `src.*` import shim (pre-1.0 break).
- Migration framework: **yoyo-migrations**. Plain SQL steps with paired rollback SQL fit a hand-written SQLite schema with no ORM. Alembic needs SQLAlchemy engines and its autogenerate needs ORM metadata HARIS does not have. yoyo adds one small dependency and records state in its own table.
- Layout: `src/haris/db/migrations/0001_baseline_v6.sql` (current v6 schema) and `.rollback.sql` pairs for each later step. On start: if `schema_version.version == 6` and no yoyo table, mark `0001` applied without running it; older versions run the legacy upgrade path once, then mark `0001`.
- New migrations: `0002_finding_identity` (`fingerprint`, `confidence_score`, `verification_json`, `suppression_json`, `observation_id` columns), `0003_scan_owner_state` (`owner_user_id`, `scan_state`), `0004_token_hash` (session token hash), `0005_api_tokens`, `0006_authorized_targets`, `0007_job_queue`.
- Token rehash (`0004`): add `token_hash`, set `token_hash = sha256(token)` for every row in a Python step, then null the plaintext column. Existing sessions stay valid because lookup hashes the presented raw token.
- Rollback: `yoyo rollback` per step; `0004` rollback cannot restore plaintext tokens, so it deletes all sessions (users log in again). Before migrating, the store copies the DB file to `<db>.pre-0.7.bak`.
- Stored findings from 0.6 get `fingerprint` recomputed lazily on read; `finding_id` of old rows is left as-is, so diffs against 0.6 reports show everything as new.

## Risks / Trade-offs

- [Regression: 21 test files and `reporting/*`, `llm/*`, `web/app.py`, `db/store.py` read `Finding`/`ScanSession`] → new fields have defaults; `to_dict`/`from_dict` keep old keys; golden JSON report fixture compared before/after.
- [`finding_id` changes from random to fingerprint-derived; two raw findings may now share it] → per-observation identity moves to `observation_id`; `CorrelatedFinding.sources` updated with its callers in the same task.
- [Correlator no longer mutates input findings; callers relying on mutated `CONFIRMED`] → reports read `session.correlated`; regression test asserts input findings unchanged.
- [Risk posture shifts once confidence weights apply] → CHANGELOG states it; golden posture tests updated with explicit reasons.
- [Built-in checks switching to `ScopedClient` change request counts and timing] → mocked-HTTP tests (`responses`/`requests-mock`) pin requests per check; rate limiter injectable clock.
- [Soft-404 baseline hides true positives on catch-all hosts without validators] → validators for high-severity paths; benchmark recall target within 5% of baseline.
- [SSRF guard blocks legitimate internal-target CLI users] → `--allow-private`; clear error naming the flag.
- [DNS pinning breaks virtual-host or CDN setups that rotate IPs] → resolve once per scan only; cert validated against hostname.
- [Parallel scanners overload targets] → global rate split, default `--parallel 3`.
- [Agent mode executes model-generated code] → off by default, two flags, container boundary, proxy, budgets, kill switch, mandatory security review before release.
- [LLM verdict suppresses true positives (Sifting the Noise)] → verdicts never change tier or delete; bounded confidence adjustment.
- [External tool rate flags differ by version] → flags verified per pinned minimum version; unsupported flags fail the pre-flight with exit 3.
- [Breaking `/api/*` → `/api/v1/*` breaks scripts] → CHANGELOG migration note; templates updated in the same task.

## Migration Plan

1. Package rename and version single-source (no behaviour change; full test pass).
2. Dependency upgrade gate.
3. yoyo adoption with `0001` baseline; `.pre-0.7.bak` copy; then `0002`-`0007`.
4. `ScopedClient` and baseline module; built-in checks moved onto them.
5. Finding identity, correlator, risk, ignore, diff, exit codes; engine stages.
6. Web routers, auth, CSRF, target authorisation, API tokens, `/api/v1`.
7. Replay verifier and LLM verdict; then agent validator behind flags; security review.
8. AI module and adapters.

Backward compatibility: JSON report keeps all 0.6 keys; `from_dict` accepts 0.6 reports (missing new keys get defaults, `verification.tier = unverified`). Rollback: reinstall 0.6.2 and restore `<db>.pre-0.7.bak`, or `yoyo rollback` to `0001` (sessions deleted by the `0004` rollback).

## Open Questions

Resolved by the maintainer's delegate on 2026-11-08:

- Sessions stay valid after migration (tokens hashed in place); proposal Impact corrected.
- `--allow-private` is off by default for the CLI and the web UI; the flag enables it.
- Exit-code precedence `3 > 2 > 1 > 0` stands; an incomplete scan returns 2 even when findings exceed `--fail-on`.
- External tools use rate and concurrency flags only; no scope proxy for them. Exact flags are verified against each tool's `--help` in the adapter task, and the pre-flight fails with exit 3 on an unsupported flag.
- OWASP MCP Top 10 maturity stays [UNVERIFIED]; the mapping uses the 2025 ids listed.
- LLM ids move to the 2026 list on 2026-11-09 (maintainer decision), reversing the 2025 pin; the spec examples and the check mapping carry the new ids.
- With `--agent-allow-unsafe-methods`, `POST` is allowed only to replay a finding originally observed on a `POST` request to the same URL; no other unsafe methods.
