# Delta for LLM backend

## ADDED Requirements

### Requirement: One LiteLLM call path
Every model call SHALL pass through one `litellm` backend that calls `litellm.completion` with `num_retries=0`, `timeout` equal to `llm_models.yaml` `runtime.timeout_s` and `drop_params=True`. No module outside that backend SHALL import `litellm`, `anthropic` or `openai`, and no module in `src/haris/llm/` SHALL send a model request with `requests`.

#### Scenario: Static import audit
- **GIVEN** the source tree under `src/haris`
- **WHEN** every Python module is parsed
- **THEN** exactly one module imports `litellm`
- **AND** no module imports `anthropic` or `openai`

#### Scenario: Call parameters
- **GIVEN** `runtime.timeout_s` is 60
- **WHEN** any task (summary, enrichment, triage, chat, verdict, agent turn) sends a request
- **THEN** `litellm.completion` receives `num_retries=0`, `timeout=60` and `drop_params=True`

### Requirement: Backend names and legacy names
`BACKEND_REGISTRY` SHALL contain only `litellm`. A requested backend name of `anthropic`, `openai`, `ollama` or `bedrock`, from `--llm-backend`, `--backend`, `llm.backend`, a saved template or a web request, MUST be rejected before any request is sent with an error that names `litellm` and `llm.model`. The CLI MUST exit `3`; the web API MUST answer `400`.

#### Scenario: Legacy name rejected
- **GIVEN** the backend name `<name>` from `<source>`
- **WHEN** the backend is created
- **THEN** the outcome is `<outcome>`
- **AND** no network request was made

#### Examples:
| name | source | outcome |
|------|--------|---------|
| anthropic | `--llm-backend` | exit 3, message names `litellm` and `llm.model` |
| openai | `llm.backend` in config | exit 3, message names `litellm` and `llm.model` |
| ollama | `--backend` of `ask` | exit 3, message names `litellm` and `llm.model` |
| bedrock | web form `backend` | HTTP 400, message names `litellm` and `llm.model` |
| litellm | `--llm-backend` | backend created |

### Requirement: Model string required
An LLM feature SHALL run only when the effective model is a LiteLLM model string of the form `<route>/<id>`. The effective model is the routed model of the task, else `llm.model`. No built-in default model SHALL exist. A blank model, or a value without `/`, MUST fail with an error that shows one example each for `bedrock/<inference profile id>`, `openai/<gateway alias>` and `ollama_chat/<tag>`. The CLI MUST exit `3`; the web API MUST answer `400`.

#### Scenario: Model validation
- **GIVEN** `llm.backend` is `litellm`, no routing and `llm.model` set to `<model>`
- **WHEN** an LLM feature starts
- **THEN** the outcome is `<outcome>`

#### Examples:
| model | outcome |
|-------|---------|
| (blank) | error with the three examples |
| claude-sonnet-5 | error with the three examples |
| bedrock/us.anthropic.claude-sonnet-5 | request sent with that string |
| openai/my-gateway-alias | request sent with that string |
| ollama_chat/llama3.1 | request sent with that string |

### Requirement: Credentials and endpoint
HARIS SHALL read exactly one secret variable, the one named by `llm.api_key_env` (default `LITELLM_API_KEY`), and pass its value to LiteLLM as `api_key` only when the variable is set. HARIS SHALL pass `llm.api_base` to LiteLLM as `api_base` only when it is non-empty. HARIS code MUST NOT reference `AWS_*`, `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`; LiteLLM resolves those from the process environment. No secret value MUST appear in logs, HTTP error bodies, reports, the database or prompts: any exception text shown or logged MUST have the `api_key` value replaced by `[REDACTED]`.

#### Scenario: Gateway call
- **GIVEN** `llm.api_base` is `https://gw.internal:4000`, `llm.api_key_env` is `GW_KEY` and `GW_KEY=sk-test-123`
- **WHEN** a request is sent with model `openai/alias`
- **THEN** `litellm.completion` receives `api_base="https://gw.internal:4000"` and `api_key="sk-test-123"`

#### Scenario: Direct Bedrock call
- **GIVEN** `llm.api_base` is empty and `LITELLM_API_KEY` is unset
- **WHEN** a request is sent with model `bedrock/us.anthropic.claude-sonnet-5`
- **THEN** `litellm.completion` receives neither `api_base` nor `api_key`

#### Scenario: Secret in an error
- **GIVEN** `GW_KEY=sk-test-123` and a provider error whose text contains `sk-test-123`
- **WHEN** the error is logged and returned by the web API
- **THEN** neither the application log nor the response body contains `sk-test-123`

#### Scenario: No provider key names in code
- **GIVEN** the source tree under `src/haris`
- **WHEN** it is searched for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `AWS_`
- **THEN** no Python module matches

### Requirement: Web UI shows, never accepts, credentials
The web UI and API SHALL NOT accept or store an API key or API base. The settings page and `GET /api/v1/llm/backends` SHALL show the effective model string and the endpoint as scheme and host only, with no userinfo, path or query. `GET /api/v1/llm/backends` MUST list `litellm` with `available` true only when the `litellm` package is importable and `llm.model` passes validation, else `available` false with a reason.

#### Scenario: Endpoint display
- **GIVEN** `llm.api_base` is `https://user:pw@gw.internal:4000/v1?x=1`
- **WHEN** the settings page is rendered
- **THEN** it shows `https://gw.internal:4000`
- **AND** the strings `user`, `pw` and `x=1` do not appear

#### Scenario: Availability
- **GIVEN** the `litellm` package is `<package>` and `llm.model` is `<model>`
- **WHEN** `GET /api/v1/llm/backends` is called
- **THEN** `litellm` has `available` `<available>`

#### Examples:
| package | model | available |
|---------|-------|-----------|
| not installed | bedrock/us.anthropic.claude-sonnet-5 | false |
| installed | (blank) | false |
| installed | bedrock/us.anthropic.claude-sonnet-5 | true |

### Requirement: Optional pinned dependency
`litellm` SHALL be declared only in the optional extra `llm`, with an exact `==` version, and `uv.lock` SHALL record hashes for it. A check in CI MUST fail when the resolved `litellm` version is `1.82.7`, `1.82.8` or `1.107.0`. HARIS MUST run every non-LLM feature when `litellm` is not installed.

#### Scenario: Deny-list check
- **GIVEN** the resolved `litellm` version is `<version>`
- **WHEN** the dependency check runs
- **THEN** it exits `<code>`

#### Examples:
| version | code |
|---------|------|
| 1.82.7 | 1 |
| 1.82.8 | 1 |
| 1.107.0 | 1 |
| a pinned version not in the list | 0 |

#### Scenario: Pin form
- **GIVEN** `pyproject.toml`
- **WHEN** the dependency check parses the `llm` extra
- **THEN** the `litellm` entry uses `==`
- **AND** no `litellm` entry exists in the main dependencies

### Requirement: Retry and budget stay in HARIS
Transient failures SHALL be retried by the HARIS retrier using LiteLLM's `status_code` on the exception, with the backoff, `Retry-After` handling and `max_retries` of `runtime`. An error whose `Retry-After` exceeds `runtime.max_retry_after_s` MUST NOT be retried. The per-scan budget MUST settle on the `usage` the response reports.

#### Scenario: Retry sequence
- **GIVEN** `max_retries` is 3 and the provider answers `<answers>`
- **WHEN** a request is sent
- **THEN** `litellm.completion` is called `<calls>` times and the outcome is `<outcome>`

#### Examples:
| answers | calls | outcome |
|---------|-------|---------|
| 429 then 200 | 2 | success |
| 503, 503, 503, 503 | 4 | error raised |
| 400 | 1 | error raised |
| 429 with Retry-After above `max_retry_after_s` | 1 | error raised |

### Requirement: Price resolution
The cost of a call SHALL come from the first matching `pricing` entry, else from LiteLLM's price table, else no price (the token cap alone applies).

#### Scenario: Price order
- **GIVEN** model `<model>`, a config price of `<config>` and a LiteLLM table price of `<table>`
- **WHEN** the budget settles a call of 1,000,000 prompt and 0 output tokens
- **THEN** the recorded cost is `<cost>`

#### Examples:
| model | config | table | cost |
|-------|--------|-------|------|
| openai/alias | 2.0 per Mtok input | none | 2.0 |
| bedrock/x | 2.0 per Mtok input | 3.0 per Mtok input | 2.0 |
| bedrock/x | none | 3.0 per Mtok input | 3.0 |
| openai/alias | none | none | 0.0 and the token cap applies |

### Requirement: Structured output
WHEN a request carries a response schema, HARIS SHALL send `response_format` of type `json_schema` with name `haris_output`, `strict` false and that schema, and SHALL validate and parse the reply itself. A model or route that does not support `response_format` MUST NOT fail the request; an unparseable reply MUST be handled as an invalid output by the calling stage.

#### Scenario: Schema request
- **GIVEN** a structured request with schema S
- **WHEN** it is sent
- **THEN** `litellm.completion` receives `response_format={"type": "json_schema", "json_schema": {"name": "haris_output", "schema": S, "strict": false}}`

#### Scenario: Unsupported format
- **GIVEN** a route that ignores `response_format` and returns prose
- **WHEN** the LLM verdict stage parses the reply
- **THEN** the stored assessment status is `invalid`
- **AND** the finding keeps its tier

### Requirement: Per-task routing
`llm.model_routing` values SHALL be LiteLLM model strings validated as in "Model string required". All tasks SHALL share `llm.api_base`, `llm.api_key_env` and one per-scan budget. A routed value that fails validation MUST be logged and that task MUST use the default model.

#### Scenario: Routing
- **GIVEN** `llm.model` is `bedrock/us.anthropic.claude-sonnet-5` and `model_routing` is `<routing>`
- **WHEN** the `summary` task starts
- **THEN** the model used is `<model>`

#### Examples:
| routing | model |
|---------|-------|
| `summary: bedrock/us.anthropic.claude-haiku-5-5` | bedrock/us.anthropic.claude-haiku-5-5 |
| `summary: claude-haiku` | bedrock/us.anthropic.claude-sonnet-5 |
| (none) | bedrock/us.anthropic.claude-sonnet-5 |

### Requirement: Saved template migration
Migration `0009` SHALL rewrite `scan_config_templates.llm_backend` values `anthropic`, `openai`, `ollama` and `bedrock` to `litellm`, and SHALL leave `''` and `litellm` unchanged. Running it twice MUST change nothing further. Scan sessions and reports MUST be unchanged.

#### Scenario: Template rows
- **GIVEN** a template with `llm_backend` `<before>`
- **WHEN** migration 0009 runs
- **THEN** its `llm_backend` is `<after>`

#### Examples:
| before | after |
|--------|-------|
| anthropic | litellm |
| openai | litellm |
| ollama | litellm |
| bedrock | litellm |
| (empty) | (empty) |
| litellm | litellm |

#### Scenario: Idempotent
- **GIVEN** the database after migration 0009 has run
- **WHEN** the migration is applied again
- **THEN** no row changes
