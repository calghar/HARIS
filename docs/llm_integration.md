# LLM Integration Architecture

## Design: Direct LLM Adapter

HARIS uses a direct LLM integration layer (`src/haris/llm/`) for report analysis.  Users run a scan, then ask questions about the results through the CLI or web UI.  The LLM interprets structured scan data and generates human-readable analysis, remediation plans, and test cases.

### Architecture

```txt
CLI user          Web UI user
    |                    |
haris llm            FastAPI /api/v1/
    |                    |
    +----+-------+-------+
         |               |
     ReportQA       PromptBuilder
         |
   LiteLLMBackend
         |
   LiteLLM (gateway, Bedrock, Ollama)
```

- **`src/haris/llm/backend.py`** defines `BaseLLMBackend`. `src/haris/llm/base.py` holds `BACKEND_REGISTRY` and re-exports it. The only concrete class is `LiteLLMBackend` in `src/haris/llm/litellm_backend.py`.
- **`src/haris/llm/prompts.py`** handles all prompt construction.  It takes structured scan data and returns formatted prompts.  No LLM calls happen here — this makes prompts auditable and testable.
- **`src/haris/llm/qa.py`** is the high-level Q&A service.  It assembles context from a `ScanSession`, calls `PromptBuilder`, and routes through the backend.  Sessions can be loaded from JSON report files or from the SQLite database.

### Design principles

1. **LLM features are optional.**  If no model is set, the tool works exactly as before.  CLI scans, web UI, and reports function without any LLM dependency.

2. **The report is the single source of truth.**  Prompts explicitly instruct the LLM to only reference findings that exist in the report data.  The system prompt forbids fabricating vulnerabilities.

3. **Prompts are separate from data retrieval.**  `PromptBuilder` is a pure function from structured data to strings.  This makes it straightforward to audit prompts, update them, and test them without hitting an LLM.

4. **One call path.**  `BaseLLMBackend` has one method, `complete()`. `LiteLLMBackend` implements it for every provider.

5. **Database-backed queries.**  The `ReportQA.from_db()` classmethod loads sessions from the SQLite database, enabling the LLM to answer questions from stored scan history.

## Backend and model

`litellm` is the only backend. The provider sits in the model string, written `<route>/<id>`. `llm.model` has no default and must be set. The `anthropic`, `openai`, `ollama` and `bedrock` backend names are rejected: the CLI exits with code 3 and the web API answers 400. See [`upgrading.md`](upgrading.md) for the saved-template migration.

| Old | New |
| --- | --- |
| `--llm-backend anthropic` and a model | `--llm-backend litellm` and `llm.model: bedrock/<inference profile id>`, or through a gateway `openai/<alias>` |
| `--llm-backend openai` | `llm.model: openai/<gateway alias>` |
| `--llm-backend ollama` | `llm.model: ollama_chat/<tag>` |
| `--llm-backend bedrock` | `llm.model: bedrock/<inference profile id>` |

Model ids in this page are examples. The Bedrock ids are unverified.

### Gateway

```yaml
llm:
  backend: litellm
  model: openai/<alias>
  api_base: https://gw.internal:4000
  api_key_env: GW_KEY
```

```bash
export GW_KEY=...
```

### Bedrock

```yaml
llm:
  backend: litellm
  model: bedrock/<inference profile id>
```

Leave `api_base` empty and set no HARIS key variable. LiteLLM resolves provider credentials from the process environment; see the LiteLLM documentation.

### Ollama

```yaml
llm:
  backend: litellm
  model: ollama_chat/llama3.1
  api_base: http://localhost:11434
```

### Credentials

HARIS reads one variable, named by `llm.api_key_env` (default `LITELLM_API_KEY`). The web UI never accepts keys or endpoints; it shows the model and `scheme://host`. Logs and error messages are scrubbed of the key value.

### Install and container

The `litellm` package is optional. It sits in the `llm` extra with an exact pin, a deny-list and hashes in `uv.lock`; the published image includes it. Install it with `uv sync --extra llm`.

A compromised release executes code at interpreter start. Run HARIS in the container.

The pin is a release at least 7 days old. `scripts/check_litellm.py` rejects the deny-listed versions 1.82.7, 1.82.8 and 1.107.0, and a lock file without hashes.

## Usage examples

### CLI

```bash
# Ask a question about a completed scan
haris llm ask \
  --scan-id 20250222-143025 \
  --question "Explain the top 3 findings for an executive"

# Generate a Jira remediation plan
haris llm remediate \
  --scan-id 20250222-143025 \
  --format jira

# Summarize for developers
haris llm summarize \
  --scan-id 20250222-143025 \
  --audience developer

# Use a different model
haris llm ask \
  --scan-id 20250222-143025 \
  --question "What needs fixing first?" \
  --model ollama_chat/llama3.1
```

### Web UI

The "Ask the Report" tab on any completed scan page provides:

- **Backend** entry that shows whether `litellm` is available, with the model and endpoint
- Preset question buttons for common queries (Top 3 Risks, Auth Issues, Jira Plan, Compare Scans, etc.)
- A freeform text input for custom questions
- Response display with model/token metadata

When a scan was started with a scan configuration template, the template context (name, profile, per-scanner overrides) is included in the chat context so the LLM can reference the scan configuration in its answers.

The "Compare Scans" preset button provides a quick way to ask the LLM to compare findings between the current scan and a previous scan of the same target.

`GET /api/v1/llm/backends` lists `litellm`. It is available when the `litellm` package is importable and `llm.model` is valid; otherwise it carries a reason.

## Model routing

`llm.model_routing` maps a task name to a model id. The enrichment pipeline looks up `enrichment`, `attack_chains`, `triage` and `false_positives`. A missing key uses `llm.model`. `src/haris/resources/config/default_config.yaml` leaves the block commented out.

## In-Pipeline Enrichment

Enable LLM enrichment during a scan to add attack narratives, business impact, and exploitation complexity to findings above the severity threshold:

```bash
haris --url https://example.com --profile quick --yes --llm-enrich
```

Configure via `llm.enrichment_enabled: true` in `config/default_config.yaml` or the enrichment toggle on the New Scan form.
