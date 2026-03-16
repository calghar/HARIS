# Contributing to HARIS

## Setup

```bash
git clone <repo-url> && cd HARIS
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[all]"
```

Copy `.env.example` to `.env` and fill in any API keys you need for testing.

## Running Tests

```bash
uv run python -m pytest tests/ -v
```

All tests must pass before submitting a PR. Tests use pytest with mocked external tools — no live scanners required.

## Code Style

- Python 3.13+ with type hints
- Pydantic `BaseModel` for data models
- `logging` module for output (no bare `print`)
- Keep modules under ~300 lines
- Lint with `ruff check src/ scripts/ tests/`

## Adding a Scanner

1. Create `src/scanners/{name}_scanner.py` subclassing `BaseScanner`
2. Implement `scan()` and `parse_results()`
3. Decorate with `@register_scanner`
4. Register in `src/scanners/__init__.py`
5. Add config in `config/default_config.yaml`
6. Add tests in `tests/test_{name}_scanner.py`

See `src/scanners/nuclei_scanner.py` for a complete example.

## Adding a Check

Same pattern as scanners, but in `src/checks/` with `@register_check`.

## Adding an LLM Prompt

1. Create a `.j2` template in `src/llm/templates/qa/` or `src/llm/templates/enrichment/`
2. Add a method to `PromptBuilder` or `EnrichmentPromptBuilder` that calls `render_template()`
3. All prompt methods return `(system_prompt, user_prompt)` tuples

## Commit Messages

Use conventional style: `fix:`, `feat:`, `refactor:`, `test:`, `docs:`.
Keep the first line under 72 characters.

## Pull Requests

- One feature or fix per PR
- Include tests for new functionality
- Update `CHANGELOG.md` under an `Unreleased` section
- Ensure `uv run python -m pytest tests/ -v` passes
