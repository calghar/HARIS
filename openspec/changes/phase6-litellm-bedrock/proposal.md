## Why

The `anthropic` and `openai` SDKs tie the LLM layer to two vendors and to provider API keys, and the project has no route to Bedrock or to a LiteLLM gateway. The 0.7.0 benchmark also left measured gaps: Wapiti findings stay unverified, redirect catch-all hosts pass, replay checks only the first PoC request, and two external tools can reach a re-resolved private address.

## What Changes

- **MODIFIED** LLM backends: one `litellm` backend replaces `anthropic`, `openai` and `ollama`. `llm.model` is a LiteLLM model string (`bedrock/...`, `openai/<gateway alias>`, `ollama_chat/...`). **BREAKING**: legacy backend names fail with a configuration error.
- **ADDED** `llm.api_base` and `llm.api_key_env`. HARIS reads the one variable named by `api_key_env`. LiteLLM reads AWS and provider credentials itself.
- **REMOVED** the per-provider capability table, the provider model-list lookup and the built-in default model ids.
- **ADDED** `litellm` as an optional, exactly pinned extra with a deny-list check for the three compromised releases (1.82.7, 1.82.8, 1.107.0).
- **MODIFIED** saved scan templates: migration `0009` rewrites legacy `llm_backend` values to `litellm`.
- **ADDED** verification: calibrated `abstain_below`, replay of Wapiti classes, redirect catch-all refutation, multi-request replay with its own control timeout.
- **ADDED** external tools: vetted-address binding (task 4.13), a bound on nuclei phase 2, and sslyze skipped when the target has no TLS endpoint.
- **ADDED** OWASP category derived from the canonical class.
- Not specified here, tracked as acceptance work with recorded artifacts: 4.4, 4.5, 4.11, 4.12, and the structural refactors 4.14 to 4.17.

## Capabilities

- New: `llm-backend`.
- Modified (ADDED requirements only): `verification`, `scoped-http`, `finding-identity`. Their folders match `openspec/specs/<capability>/`.

## Blast radius

Confirmed with `rg` on 2026-11-11.

| Surface | Readers and writers |
|---|---|
| `create_backend`, `BACKEND_REGISTRY`, `get_available_backends`, `get_default_backend_name` | `llm/base.py`, `llm/router.py`, `core/runner.py`, `cli.py`, `web/llm_support.py`, `web/routers/llm_chat.py`; tests `test_llm.py`, `test_router.py`, `test_web_llm.py` |
| `llm/providers.py` classes, `catalog.py` (`API_KEY_ENV`, `resolve_model`, `capabilities`) | `llm/backend.py`, `llm/base.py`, `llm/settings.py`; tests `test_llm_catalog.py`, `test_llm.py` |
| `BaseLLMBackend` and `ProviderBackend` consumers (kept) | `agent/coordinator.py`, `agent/turn.py`, `verify/llm_verdict.py`, `verify/pipeline.py`, `core/llm_enrichment.py` |
| Config keys `llm.backend`, `llm.model`, `llm.model_routing` | `models/config.py`, `resources/config/default_config.yaml`, `core/runner.py`, `core/llm_enrichment.py`, `web/routers/pages.py`, `web/templates/settings.html` |
| Saved template column `llm_backend` | `db/baseline.py`, `db/templates.py`, `models/templates.py`, `web/routers/templates_api.py`, `web/routers/scans_api.py`, `web/page_data.py`, `web/static/js/template_form.js`, `scan_new.js` |
| Docs and CI naming provider keys | `README.md` (lines 74, 150, 151), `docs/llm_integration.md`, `.github/dependabot.yml` |
| Dependencies | `pyproject.toml` lines 32 and 33, `uv.lock` |

Do-not-touch: `LLMBudget` reserve-and-settle accounting, `Retrier`, the fence and redaction code, and the verdict output schema.

## Impact

- Persisted format: SQLite `scan_config_templates.llm_backend`. Migration `0009` rewrites `anthropic`, `openai`, `ollama` and `bedrock` to `litellm`. Rollback is one-way: the old name is not recoverable, so back up the database first.
- JSON report format: unchanged. `LLMResponse.model` keeps recording the model string the provider returned.
- Config: `llm.backend` default becomes `litellm`; `llm.model` has no default; new `llm.api_base`, `llm.api_key_env`. `pricing` keeps its keys.
- Dependencies: `anthropic` and `openai` leave the main group. `litellm` joins the optional `llm` extra. `requests` stays.
- Consumers: anyone using `--llm-backend anthropic|openai|ollama` or `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` must move to a LiteLLM model string. The README and `docs/llm_integration.md` carry the mapping.

## Open Questions

- Real Bedrock model ids and access are unverified until task 4.2 runs against the maintainer's gateway.
