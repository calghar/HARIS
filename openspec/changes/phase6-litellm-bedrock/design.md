## Context

`src/haris/llm/providers.py` holds three vendor backends over `ProviderBackend` (retry, budget, cache, structured calls). `catalog.py` lists models through the vendor SDKs, and `llm_models.yaml` carries per-provider model ids and a capability table. Callers depend on `BaseLLMBackend`/`ProviderBackend` (agent, verify, enrichment) and on `create_backend` (CLI, runner, web). Those interfaces stay. The Phase 5 gate (2569 tests) is the regression baseline.

Not touched: `LLMBudget` accounting, `Retrier`, fence and redaction code, the verdict schema, the JSON report format.

## Goals / Non-Goals

**Goals:**
- One LiteLLM call path for a gateway, Bedrock, Ollama and other provider keys.
- Credentials never stored or logged by HARIS; one named variable read.
- The measured Phase 6 gaps from the 0.7.0 benchmark.

**Non-Goals:**
- A UI for keys or endpoints.
- A built-in default model.
- Out-of-band callbacks (SSRF, XXE stay `unverified`).
- Structural refactors 4.14 to 4.17 and the bench work 4.4, 4.5, 4.11, 4.12 (tasks only).

## Decisions

### D1. `LiteLLMBackend` in `src/haris/llm/litellm_backend.py`
Subclass of `ProviderBackend`; `_send` builds one kwargs dict (`model`, `messages`, `max_tokens`, `temperature`, `response_format`, `api_base`, `api_key`, `num_retries=0`, `timeout`, `drop_params=True`) and maps `choices[0].message.content`, `usage` and `model` to `LLMResponse`. The module imports `litellm` lazily inside `_send` and the price helper, so a missing package makes only the backend unavailable. Delete `providers.py`, the SDK lister in `catalog.py`, `ProviderModels`, `Capability`, and the `providers` and `capabilities` blocks of `llm_models.yaml`. Alternative: keep per-vendor classes behind LiteLLM; rejected because the one-path test (4.1) would need exemptions.

### D2. Validation and errors
`validate_model(model)` raises `LLMConfigError(ValueError)` for a blank value or one without `/`, with the three examples. `create_backend` raises it for legacy names. The CLI maps it to exit 3 where it already maps usage errors; `web/llm_support.llm_errors` maps it to HTTP 400. Alternative: accept bare names and let LiteLLM guess the route; rejected because the same bare name can resolve to different providers.

### D3. Credentials and logging
`api_key = os.environ.get(llm.api_key_env) or None`. `api_base` passes through unchanged. `scrub(text, api_key)` replaces the key value and is used where exceptions are formatted: `retry.py` warning, `llm_support.llm_errors` log (replace `logger.exception` with a scrubbed `logger.error`, no traceback). AWS and provider keys are resolved by LiteLLM; a test greps `src/haris` for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `AWS_`. Region comes from LiteLLM's own lookup (`AWS_REGION_NAME`, profile); no config key (YAGNI).

### D4. Pricing
`LLMBudget._cost` keeps the config lookup first. When none matches it calls `litellm_backend.table_cost(model, prompt, output)`, which wraps `litellm.cost_per_token` and returns `None` on any failure.

### D5. Settings and config
`LLMConfig` gains `api_base: str = ""` and `api_key_env: str = "LITELLM_API_KEY"`; `backend` defaults to `litellm`; `model` has no default. `llm_models.yaml` keeps `runtime`, `budget`, `pricing`, `redaction`, `limits`. The web builds the backend from the same `LLMConfig` that `pages.py` reads. `GET /api/v1/llm/backends` returns one entry; the settings page shows the model and `scheme://host`.

### D6. Dependency guard
`pyproject.toml`: `llm = ["litellm==<pin>"]`; `anthropic` and `openai` leave the main group. `scripts/check_litellm.py` reads `uv.lock`, fails on a deny-listed version and on a missing hash; CI and the pre-release gate run it. Dependabot ignores `litellm` and uses a 14-day cooldown for the rest. The pin must be a release at least 7 days old, checked against PyPI at pin time; transitive packages it adds must be at least 7 days old in the lock at that time. `docs/llm_integration.md` states that the package runs code at interpreter start when compromised, and that HARIS should run in the container.

### D7. Migration `0009_llm_backend_names.py`
`UPDATE scan_config_templates SET llm_backend='litellm' WHERE llm_backend IN ('anthropic','openai','ollama','bedrock')`. Rollback is a no-op; the original names are lost.

### D8. Verification additions
- Threshold: `bench/calibrate_abstain.py` reads the committed verdict artifacts, applies the grid rule of the spec, writes `bench/results/<run>/abstain.json`.
- Oracles: `path_traversal` and `open_redirect` become `content_validator`-style oracles in `verify/oracles.py`; `command_injection` reuses `timing` with `verify.timing.cmd_payloads`. `vuln_classes.yaml` gains the `oracle:` keys. `ssrf` and `xxe` get none.
- Redirect catch-all: `baseline.judge` compares `Location` (random segment removed) before the early non-2xx return; `verify/replay.py` applies the same rule for external findings.
- Multi-request replay: loop over all PoC requests, aggregate per the spec table; soft-404 controls use `verify.request_timeout_s`; `finish()` keeps skip notes when the state is `failed`.
- Nikto noise: class and severity set in `scanners/nikto_scanner.py`. The existing nikto severity map must not override `info` (check before merge).

### D9. External tools
- Binding: per tool, task 4.13 reads `--help` and picks either the vetted IP as the tool's target (with the original name as Host or SNI), or a container network that blocks private ranges. A tool with neither does not start (spec). No flag is assumed here.
- `partial` and `skipped`: stored in `ScannerResult.metadata["status"]` and `["note"]`, so no schema change. `ScanSession.scanner_status` returns the metadata status when present. `Engine._final_state` counts `completed` and `partial` as completed and drops `skipped` from the denominator; all-skipped is `completed`.
- Nuclei phase 2: `scanners.nuclei.phase2_timeout_s` in `resources/config/scanners/nuclei.yaml`; the scanner kills the process group and keeps parsed output.
- sslyze applicability: decided from the target scheme and the nmap port result already in the session context.

### D10. OWASP by class
`Engine._auto_map_owasp` first maps from the canonical class id, then from tags and title as today. `vuln_classes.yaml` gains an `unmapped:` list; a test asserts every class id is in the mapping or the list.

## Risks / Trade-offs

- [Existing `--llm-backend anthropic` users break] → one error naming `litellm`, `llm.model` and an example; README and `docs/llm_integration.md` carry the old-to-new table; CHANGELOG marks BREAKING.
- [`ProviderBackend` consumers regress] → class and its tests stay; only `_send` moves. `test_router.py`, `test_llm.py`, `test_web_llm.py` and the agent and verify suites run unchanged except for backend names.
- [Saved templates with legacy names] → migration 0009 plus the 400 path for any leftover value.
- [`drop_params` hides a dropped `response_format`] → output is always validated; the verdict stage stores `invalid`.
- [Compromised `litellm` release] → exact pin, hashes, deny-list gate, cooldown, container note, no secrets read by HARIS beyond one variable.
- [Bedrock ids unverified] → task 4.2 runs against the gateway first; docs show ids as examples only.
- [Replay with more requests spends budget] → the existing `verify.max_requests` cap still counts every request.
- [`partial` hides lost coverage] → the note is in every report; the status appears in `scanner_status`.
- [Wapiti blocked when no blocking network exists] → it does not start and the scan records an error, never a silent unbound run.

## Migration Plan

1. Land D1 to D6 and migration 0009 together. 2. Run `uv lock` and the deny-list gate. 3. Update README, docs and CHANGELOG (BREAKING). 4. Run the full gate, then a live call through the gateway (task 4.2). Rollback: revert the change set; restore the database backup if names must return to `anthropic`, `openai` or `ollama`.

## Open Questions

- Does the published image build with the `llm` extra? Default in this change: yes, with the pin and gate.
- Podman compatibility for tasks 4.3 to 4.6, 4.11 and 4.12 is unverified; task 4.0 checks it first.
