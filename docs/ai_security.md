# AI security

`haris.ai_security` finds AI endpoints and MCP servers and checks them. Prompts are sent only on request.

## Run

```sh
haris --url https://example.com --profile ai-security                                  # passive only
haris --url https://example.com --profile ai-security --ai-active --i-have-authorization   # also sends prompts
```

`--ai-active` without `--i-have-authorization` exits 3 before any request. `--ai-system-prompt-marker TEXT`
(repeatable) names text that proves a system prompt leak. Run active probes only against systems you are
authorised to test.

## What runs

| Part | Needs flags | Sends prompts |
|------|-------------|---------------|
| Discovery of 16 signatures in `ai_signatures.yaml`, behind the soft-404 baseline and a body validator | no | no |
| Passive checks: unauthenticated inference or admin API, provider keys, system prompts and model settings in bundles, verbose errors, CORS, plaintext MCP | no | no |
| MCP survey: `initialize`, `notifications/initialized`, `tools/list`, plus `resources/list` and `prompts/list` when advertised | no | no |
| Active probes: canary injection, system prompt leak, output-handling XSS marker, four jailbreak framings, rate-limit burst, `max_tokens` check | yes | yes |
| `garak` and `promptfoo` adapters | yes | yes |

The MCP survey never sends `tools/call`, `resources/read` or `prompts/get`.

Active probes use `ai.max_prompts` (50) and `ai.max_tokens_per_prompt` (256) from `ai_probes.yaml`. Payloads come
only from that reviewed file; only canaries and inert markers are substituted. A canary finding becomes
`replay_verified` after a second run with a fresh canary also matches. A model that echoes its input voids canary
verdicts for that endpoint.

## Adapters

| Tool | Licence | Default families |
|------|---------|------------------|
| [garak](https://github.com/NVIDIA/garak) 0.17.1 | Apache-2.0 | `promptinject.HijackLongPrompt`, `latentinjection.LatentInjectionTranslationEnFr` |
| [promptfoo](https://github.com/promptfoo/promptfoo) 0.125.1 | MIT | `prompt-extraction`, `hijacking`, `system-prompt-override`, `ascii-smuggling` |

Neither tool is vendored; install them yourself. A missing binary is a scanner error and the scan state is
`incomplete`. Allowed probes and plugins are listed in `config/scanners/garak.yaml` and `promptfoo.yaml`.

- Each finding has tier `unverified` and `confidence_score = min(0.95, 0.5 + 0.5 * r)` for fail rate `r`.
- Both tools reach the target directly, not through `ScopedClient`. garak runs one request at a time with
  `soft_probe_prompt_cap` set to `max_prompts`. promptfoo runs with `--max-concurrency 1` and `numTests` set so
  plugins times tests stays within `max_prompts`.
- Credentials sit only in a 0600 config file in a temporary directory, never in argv, logs or evidence.
- promptfoo runs `redteam generate` and then `eval`. Generation needs a model; set `provider` in the scanner
  options, or promptfoo uses its own default (a third-party API that needs its key). Telemetry, update checks
  and sharing are switched off. `eval` exits 100 when a test fails; that is not an error.
- [UNVERIFIED] The `redteam generate` output was not captured: it needs a remote model. The promptfoo fixture is
  real `eval` output with hand-written test cases (`tests/fixtures/scanners/README.md`).

## OWASP mapping

LLM Top 10 2026 ids (genai.owasp.org, checked 2026-11-09) and Agentic Top 10 ASI01-ASI10 (genai.owasp.org/download/52117) were
checked against the sources on 2026-11-08. CWE-1427 and CWE-770 were checked at cwe.mitre.org.

- [UNVERIFIED] MCP Top 10 (`MCP01:2025` to `MCP10:2025`): titles match owasp.org/www-project-mcp-top-10, a beta
  whose project level and final ids may change.
- The 2026 LLM Top 10 renumbers the 2025 list: Excessive Agency is `LLM03:2026`, System Prompt Leakage became Hidden
  Context Exposure (`LLM08:2026`), Unbounded Consumption is `LLM06:2026` and Improper Output Handling is `LLM10:2026`.
- The garak and promptfoo to OWASP tables in `ai_mappings.yaml` are HARIS's own classification, not the tools'.

## Limits

- `/sse` is probed with HEAD. `ScopedClient` reads whole bodies, so a GET would wait on the open event stream.
  SSE-only servers are reported without a tool walk.
- Signatures were written from vendor documentation and the bench fixture, not live installs. Entries marked
  `[UNVERIFIED]` in `ai_signatures.yaml` need a live check.
- Passive checks run twice for replay, so discovery costs about double the requests.
