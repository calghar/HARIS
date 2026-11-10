# Benchmarks

The harness in `bench/` measures how many of HARIS's findings are real (precision) and how many known weaknesses it finds (recall), per target, over repeated runs. It follows the per-request-instance ground-truth idea of [DASTestBed](https://doi.org/10.1109/isdfs69419.2026.11459007).

## Targets

| Target | Kind | Ground truth |
|---|---|---|
| OWASP Juice Shop `v20.4.0` | external | seed set of 4 entries from the [companion guide](https://pwning.owasp-juice.shop/); 0 known gaps |
| DVWA (digest of `latest`) | external | seed set of 8 entries from the [module list](https://github.com/digininja/DVWA), security level low; 0 known gaps |
| WebGoat `v2026.5` | external | seed set of 3 lesson endpoints from the [WebGoat repository](https://github.com/WebGoat/WebGoat) |
| `spa_catchall` | fixture | the fixture's real properties: plain HTTP, `Server` banner, five missing security headers; any path or debug finding is a false positive |
| `vuln_ai_app` | fixture | 7 deliberate weaknesses (prompt injection, system-prompt leak, unauthenticated inference, verbose error, output XSS, unauthenticated MCP `tools/list`, poisoned MCP tool description) plus 4 real properties (plain HTTP, `Server` banner, no rate limit, ignored `max_tokens`); the `/health` path and `ai_endpoint_discovered` records are ignored |

`spa_catchall` answers 200 with one HTML shell for every path and method, so `.env`, `.git/config` and similar checks must not report. `vuln_ai_app` is a deterministic fake model (no LLM calls) with a canary in its system prompt. The documented injection prompt is `INJECTION_PROMPT` in `bench/fixtures/vuln_ai_app/server.py`; a benign prompt never returns the canary.

`bench/compose.yaml` binds every port to `127.0.0.1` and pins each external image by tag and digest. DVWA publishes commit-sha tags only, so it is pinned by the digest of `latest`.

## Ground truth

`bench/ground_truth/<target>.yaml`, validated by `haris.bench.truth.GroundTruth`. Each entry is one request instance: `method`, `url` (path glob), `parameter`, `vuln_class`, `cwe`, `expected: true_positive`. Entries for external targets carry a `source` URL. An optional `ignore` list holds findings that are neither true nor false positives: `vuln_class`, `url` (path glob), optional `parameter` (any when omitted) and a required `reason`. The seed sets are small and are not a claim of completeness: a real finding outside them counts as a false positive.

- `vuln_class` is an `id` in `src/haris/resources/config/vuln_classes.yaml` (or an `unclassified:` token HARIS emits); `tests/test_bench_ground_truth.py` enforces it.
- A weakness HARIS cannot yet detect stays an entry, so recall shows the miss (`juice-ftp-listing`); no ground-truth file lists known gaps in its header.
- The three external files each ignore 6 target properties: plain HTTP, missing headers, `Server` banner, and the `robots.txt`, `sitemap.xml` and `security.txt` records.

## Scoring

```bash
python -m haris.bench score <report.json | reports-dir> <ground_truth.yaml> [--baseline <report.json | dir>] [--out DIR]
```

`haris bench score` takes the same arguments (exit 3 on a missing or invalid path). A directory holds one JSON report per run. Output: `score.json` and `score.md`.

- A finding matches an entry when the class token (the finding's `vuln_class`, else its `cwe_id`), the normalised URL path and the parameter all match. Scheme, host, query and trailing slash are ignored. The method is recorded but not matched.
- A finding that matches an `ignore` entry is excluded from precision and recall and counted as ignored (`ignored` in `score.json`, the Ignored column in `score.md`). Ignore is checked before truth entries.
- Findings with the same key count once. Precision is true-positive findings over unique findings; recall is matched entries over entries. True-positive rate equals recall (DASTestBed naming).
- With no findings, precision is 1.0; with no entries, recall is 1.0. Read false positives next to these values.
- F1 is the harmonic mean of precision and recall.
- False-positive reduction rate is `(baseline_fp - fp) / baseline_fp`, where `baseline_fp` is the mean over the baseline runs; undefined when the baseline has none.
- Request count, cost and wall time come from the report's `meta.request_count`, `meta.cost_usd` and `meta.duration_seconds`. A missing key shows as `n/a`.
- Multiple runs give mean and sample standard deviation per metric; one run gives a standard deviation of 0.

## Reproduce

```bash
uv sync --extra web --extra reporting
uv run python bench/run.py --runs 3
# optional: --targets spa_catchall,vuln_ai_app  --profile <profile>  --baseline-profile <profile>
```

Each target has its own profile: `quick` by default, `ai-security` with `--ai-active --i-have-authorization` for `vuln_ai_app`. `--profile` overrides the profile of every target and keeps each target's extra flags. `--baseline-profile` adds baseline runs for the false-positive reduction rate.

`garak` and `promptfoo` may be absent on the runner. The `vuln_ai_app` run then ends `incomplete` (exit code 2); the runner accepts a non-zero `haris` exit when exactly one JSON report exists.

The runner starts the targets, waits for health, runs `haris` for each run, stores artifacts under `bench/results/<date>/` and tears the targets down. It scans only the `127.0.0.1` targets from the compose file. WebGoat takes about a minute to start.

The `callback` service (`bench/fixtures/callback`, published on `127.0.0.1:${BENCH_CALLBACK_PORT:-19090}`) is the out-of-band receiver for Wapiti's blind SSRF and XXE checks, so no run contacts `wapiti3.ovh`. The runner sets the Wapiti scanner options `external_endpoint` (`http://callback:9090/`, used by the target) and `internal_endpoint` (the published host URL, used by Wapiti) in the generated `--config`; with them set, `log4shell` is dropped (it needs a DNS endpoint). Unset, Wapiti uses its public default `wapiti3.ovh`.

`.github/workflows/bench.yml` runs nightly and on manual dispatch, publishes the raw artifacts and does not fail on score changes.

## Not claimed

- No published scores yet; this page holds methodology only. Numbers appear after a recorded run, with the artifacts attached.
- Recall on Juice Shop, DVWA and WebGoat is against a seed set, not their full vulnerability lists.
- The runner logs in before every DVWA run (`admin`/`password`, security level `low`) and WebGoat run (registers `haris-bench`, then logs in) and hands the session to `haris` through a generated `--config` (`auth.method: header`, `Cookie`) and `HARIS_AUTH_HEADER`; the session is not written to argv, `stdout.log` or the results directory.
- Third-party results (DASTestBed, XBOW) are not ours and are not compared here.
- Scanners that are not installed on the runner are recorded as scanner errors, so results reflect the tools present.
