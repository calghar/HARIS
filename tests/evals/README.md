# LLM evals

Offline regression set for the LLM layer. No network, no API keys.

Each case in `cases.json` names a stage (`triage`, `false_positives`, `chains`, `enrichment`, `variants`), the findings sent, and the raw text a fake provider replies with. The runner executes the real stage code, shared parser and prompt builders, then compares observable metrics with `expect`:

| Key | Meaning |
|---|---|
| `items` | validated items returned |
| `errors` | entries recorded in the stage report (dropped items, unparseable output) |
| `ids` | returned IDs, in order |
| `statuses` | per-finding stage status (`ok`, `invalid`, `failed`, `skipped_budget`) |
| `findings_unchanged` | the input findings are identical afterwards |
| `injection_fenced` | injected evidence appears only inside the untrusted-data fence |

Run with `pytest tests/evals -q`, or `python -m tests.evals.runner` for a one-line-per-case summary.

Add a case by appending to `cases.json`; use a model reply that reproduced a real failure (prose around JSON, truncated output, an out-of-range score, an obeyed injection).
