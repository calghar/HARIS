# LLM Integration Architecture

## Design: Direct LLM Adapter

HARIS uses a direct LLM integration layer (`src/llm/`) for report analysis.  Users run a scan, then ask questions about the results through the CLI or web UI.  The LLM interprets structured scan data and generates human-readable analysis, remediation plans, and test cases.

### Architecture

```txt
CLI user          Web UI user
    |                    |
run_scan.py llm       FastAPI /api/
    |                    |
    +----+-------+-------+
         |               |
     ReportQA       PromptBuilder
         |
   BaseLLMBackend
     |     |     |
 OpenAI  Claude  Ollama
```

- **`src/llm/base.py`** defines the abstract `BaseLLMBackend` interface.  Provider-specific code (API clients, authentication, response parsing) lives in concrete implementations.
- **`src/llm/prompts.py`** handles all prompt construction.  It takes structured scan data and returns formatted prompts.  No LLM calls happen here — this makes prompts auditable and testable.
- **`src/llm/qa.py`** is the high-level Q&A service.  It assembles context from a `ScanSession`, calls `PromptBuilder`, and routes through the backend.  Sessions can be loaded from JSON report files or from the SQLite database.

### Design principles

1. **LLM features are optional.**  If no API key is set, the tool works exactly as before.  CLI scans, web UI, and reports function without any LLM dependency.

2. **The report is the single source of truth.**  Prompts explicitly instruct the LLM to only reference findings that exist in the report data.  The system prompt forbids fabricating vulnerabilities.

3. **Prompts are separate from data retrieval.**  `PromptBuilder` is a pure function from structured data to strings.  This makes it straightforward to audit prompts, update them, and test them without hitting an LLM.

4. **Backends are pluggable.**  `BaseLLMBackend` has a single method (`complete()`).  Adding a new provider means writing one class with one method.

5. **Database-backed queries.**  The `ReportQA.from_db()` classmethod loads sessions from the SQLite database, enabling the LLM to answer questions from stored scan history.

## Supported backends

| Backend | Package | Auth | Best for |
| --------- | --------- | ------ | ---------- |
| OpenAI | `openai` | `OPENAI_API_KEY` | GPT-4o, Azure OpenAI, vLLM |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | Claude models |
| Ollama | (none) | Local server | Air-gapped / offline use |

## Usage examples

### CLI

```bash
# Ask a question about a completed scan
python scripts/run_scan.py llm ask \
  --scan-id 20250222-143025 \
  --question "Explain the top 3 findings for an executive"

# Generate a Jira remediation plan
python scripts/run_scan.py llm remediate \
  --scan-id 20250222-143025 \
  --format jira

# Summarize for developers
python scripts/run_scan.py llm summarize \
  --scan-id 20250222-143025 \
  --audience developer

# Use a different backend
python scripts/run_scan.py llm ask \
  --scan-id 20250222-143025 \
  --question "What needs fixing first?" \
  --backend anthropic
```

### Web UI

The "Ask the Report" tab on any completed scan page provides:

- **Backend selector** dropdown that auto-detects available backends (checks installed packages and API keys)
- Preset question buttons for common queries (Top 3 Risks, Auth Issues, Jira Plan, Compare Scans, etc.)
- A freeform text input for custom questions
- Response display with model/token metadata

When a scan was started with a scan configuration template, the template context (name, profile, per-scanner overrides) is included in the chat context so the LLM can reference the scan configuration in its answers.

The "Compare Scans" preset button provides a quick way to ask the LLM to compare findings between the current scan and a previous scan of the same target.

The backend auto-detection API (`GET /api/llm/backends`) checks each backend for:

1. Required Python package installed (via `importlib.util.find_spec()`)
2. Required API key set in environment (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`)

The first available backend is selected as the default.

## Model Routing

Route different task types to different models for cost optimisation:

```yaml
# config/default_config.yaml
llm:
  model_routing:
    enrichment: claude-haiku-4-5       # cheaper model for per-finding enrichment
    attack_chains: claude-sonnet-4-6   # stronger model for chain detection
    triage: claude-haiku-4-5
    summary: claude-haiku-4-5
    chat: claude-sonnet-4-6
```

When no routing is configured, all tasks use the default model.

## In-Pipeline Enrichment

Enable LLM enrichment during a scan to add attack narratives, business impact, and exploitation complexity to findings above the severity threshold:

```bash
python scripts/run_scan.py --url https://example.com --profile quick --yes --llm-enrich
```

Configure via `llm.enrichment_enabled: true` in `config/default_config.yaml` or the enrichment toggle on the New Scan form.
