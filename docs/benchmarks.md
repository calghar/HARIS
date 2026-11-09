# Benchmarks

The harness in `bench/` measures how many of HARIS's findings are real (precision) and how many known weaknesses it finds (recall), per target, over repeated runs. It follows the per-request-instance ground-truth idea of [DASTestBed](https://doi.org/10.1109/isdfs69419.2026.11459007).

## Targets

| Target | Kind | Ground truth |
|---|---|---|
| OWASP Juice Shop `v20.4.0` | external | seed set from the [companion guide](https://pwning.owasp-juice.shop/) |
| DVWA (digest of `latest`) | external | seed set from the [module list](https://github.com/digininja/DVWA), security level low |
| WebGoat `v2026.5` | external | seed set of lesson endpoints from the [WebGoat repository](https://github.com/WebGoat/WebGoat) |
| `spa_catchall` | fixture | empty: every finding is a false positive |
| `vuln_ai_app` | fixture | exact: 7 deliberate weaknesses (prompt injection, system-prompt leak, unauthenticated inference, verbose error, output XSS, unauthenticated MCP `tools/list`, poisoned MCP tool description) |

`spa_catchall` answers 200 with one HTML shell for every path and method, so `.env`, `.git/config` and similar checks must not report. `vuln_ai_app` is a deterministic fake model (no LLM calls) with a canary in its system prompt. The documented injection prompt is `INJECTION_PROMPT` in `bench/fixtures/vuln_ai_app/server.py`; a benign prompt never returns the canary.

`bench/compose.yaml` binds every port to `127.0.0.1` and pins each external image by tag and digest. DVWA publishes commit-sha tags only, so it is pinned by the digest of `latest`.

## Ground truth

`bench/ground_truth/<target>.yaml`, validated by `haris.bench.truth.GroundTruth`. Each entry is one request instance: `method`, `url` (path glob), `parameter`, `vuln_class`, `cwe`, `expected: true_positive`. Entries for external targets carry a `source` URL. The seed sets are small and are not a claim of completeness: a real finding outside them counts as a false positive.

## Scoring

```bash
python -m haris.bench score <report.json | reports-dir> <ground_truth.yaml> [--baseline <report.json | dir>] [--out DIR]
```

`haris bench score` takes the same arguments (exit 3 on a missing or invalid path). A directory holds one JSON report per run. Output: `score.json` and `score.md`.

- A finding matches an entry when the class token (the finding's `vuln_class`, else its `cwe_id`), the normalised URL path and the parameter all match. Scheme, host, query and trailing slash are ignored. The method is recorded but not matched.
- Findings with the same key count once. Precision is true-positive findings over unique findings; recall is matched entries over entries. True-positive rate equals recall (DASTestBed naming).
- With no findings, precision is 1.0; with no entries, recall is 1.0. Read false positives next to these values.
- F1 is the harmonic mean of precision and recall.
- False-positive reduction rate is `(baseline_fp - fp) / baseline_fp`, where `baseline_fp` is the mean over the baseline runs; undefined when the baseline has none.
- Request count, cost and wall time come from the report's `meta.request_count`, `meta.cost_usd` and `meta.duration_seconds`. A missing key shows as `n/a`.
- Multiple runs give mean and sample standard deviation per metric; one run gives a standard deviation of 0.

## Reproduce

```bash
uv sync --extra web --extra reporting
uv run python bench/run.py --profile quick --runs 3
# optional: --targets spa_catchall,vuln_ai_app  --baseline-profile <profile>
```

The runner starts the targets, waits for health, runs `haris` for each run, stores artifacts under `bench/results/<date>/` and tears the targets down. It scans only the `127.0.0.1` targets from the compose file. WebGoat takes about a minute to start.

`.github/workflows/bench.yml` runs nightly and on manual dispatch, publishes the raw artifacts and does not fail on score changes.

## Not claimed

- No published scores yet; this page holds methodology only. Numbers appear after a recorded run, with the artifacts attached.
- Recall on Juice Shop, DVWA and WebGoat is against a seed set, not their full vulnerability lists.
- DVWA modules and WebGoat lessons need a logged-in session; the runner does not configure authentication, so an unauthenticated run cannot reach them.
- Third-party results (DASTestBed, XBOW) are not ours and are not compared here.
- Scanners that are not installed on the runner are recorded as scanner errors, so results reflect the tools present.
