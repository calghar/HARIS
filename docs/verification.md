# Verification

A finding has one tier: `unverified`, `replay_verified`, `exploit_validated` or `refuted`. A new finding starts at `unverified`.

`Verification.advance` allows four moves: `unverified` to `replay_verified`, `unverified` to `refuted`, `unverified` to `exploit_validated`, and `replay_verified` to `exploit_validated`. Any other move raises `ValueError`.

A refuted or suppressed finding stays on the session. `Finding.is_active` is false, and the score becomes 0 for a refuted finding. JSON still lists the finding. Markdown and HTML put it in an appendix. SARIF keeps it and sets `suppressions`. Replay and the LLM verdict do not remove it.

## Replay

`--verify` accepts `off`, `replay` and `llm`. The CLI default is `replay`. `off` skips the stage. `replay` runs the oracles. `llm` runs the oracles and then the LLM verdict.

A web scan with no `verify` field uses `HARIS_WEB_VERIFY_DEFAULT`. That default is `replay`. `POST /api/v1/scans` returns 422 when `verify` is `llm` and `llm_enrich` is absent. The engine constructor defaults to `off`. The CLI and the web app pass the mode above.

Replay runs when the tier is `unverified`, the finding is not suppressed, the method is in scope, and the class has an oracle. `oracle` in `vuln_classes.yaml` is a comma-separated list. The default is `none`, and those findings are skipped.

The chain runs in that order and stops at the first positive or refuted result. A positive result sets `replay_verified`. A refuted result sets `refuted`. An inconclusive result leaves `unverified`. The cap is `max_requests` in `verify.yaml` (500).

An `unclassified:` finding from an external scanner is a special case. The external scanners are `wapiti`, `nuclei`, `nikto`, `nmap`, `sslyze` and `zap`. Replay uses only `soft404`, and only for `GET` when the path is not `/`. A control match refutes the finding. Any other outcome leaves it `unverified`.

## Oracles

| Oracle | Result |
| --- | --- |
| `reflection` | Positive when the HTML body contains a fresh marker and the control body does not. |
| `error_signature` | Positive when `error_probe` matches one `error_signatures` pattern and the control does not. |
| `timing` | Positive when every delay probe beats every random-token control by `min_gap_ratio` times `delay_s`, and the probe median reaches `delay_s`. Shipped values: `min_gap_ratio` 0.8 and `delay_s` 5.0 seconds. |
| `header_presence` | Positive when two GETs both show the named header absent or invalid. Refuted when both show it valid. |
| `soft404` | Refuted when the GET matches a host control. Otherwise inconclusive. |
| `content_validator` | Positive when the body validator passes. Refuted when the validator fails or the response matches a host control. |
| `timing_cmd` | The `timing` rule with `timing.cmd_payloads`: shell `sleep {d}` forms that run no other command. |
| `path_traversal` | Positive when a `traversal_payloads` probe returns a body matching `root:[x*]:0:0:` or `[boot loader]` and its random-token control does not. |
| `open_redirect` | Positive when the probe answers 3xx with a `Location` host equal to a fresh `haris-<16 hex>.invalid` marker host and the control does not. Neither request follows redirects. |
| `canary` | Positive when the probe contains a fresh canary and the control does not. No class in `vuln_classes.yaml` names this oracle. Active AI probes set `replay_verified` with it themselves. |

Classes that name an oracle: `xss_reflected` (`reflection`), `sqli_time` (`timing`), `sqli_error` (`error_signature`), `command_injection` (`timing_cmd`), `path_traversal` (`path_traversal`), `open_redirect` (`open_redirect`), `missing_header` (`header_presence`), `sensitive_file` (`soft404`, `content_validator`), `api_docs_exposed` (`content_validator`). `ssrf` and `xxe` name none, so they stay `unverified` with method `none`.

## Soft-404 control

`Baseline` keeps one control set per host for the scan. The base controls are three GETs: `/{token}`, `/{token}/` and `/{token}.html`. The token is `haris-` plus `token_hex(8)`. A path in another directory, or with an extension other than empty or `.html`, gets one extra control for that directory and extension, up to 10.

A probe matches a control when the status is the same. A redirect probe matches any redirect control with the same `Location` (random segment removed), whatever the status code, so the baseline does not report the path and an external finding of it is refuted. A redirect to a different `Location` keeps the old behavior. Otherwise the content type must match, and either the body hash matches or the title matches and the lengths are close. Close means a difference of at most the larger of 64 bytes and 5 percent of the control length.

The `soft404` oracle refutes only that control match. A catch-all or unstable host, worded as `host is ...`, stays inconclusive for that oracle.

## LLM verdict

`verify.llm.abstain_below` defaults to 0.7 in `LLMVerdictSettings` and in `verify.yaml`. The threshold is uncalibrated.

The stage runs only in mode `llm`. It considers findings that are still `unverified`, are not suppressed, and already have evidence. A verdict with confidence below 0.7 is stored as `abstained`. The tier stays put. A verdict of `confirmed` or `likely_fp` with status `ok` changes `confidence_score` only. The model output does not delete the finding and does not set the tier. The case cap is `max_cases` (50).

The model must return up to 5 cited spans of at most 300 characters each and a rationale of at most 2000 characters. An answer that breaks a limit, or cites text that is not in the exchange, is stored as `invalid`. The exchange text sent to the model has `\r\n` replaced by `\n`, and a cited span must be one unbroken run of that text. The stored reason names the failing field. For a cited span it also quotes the first 120 characters. The allow-list `verify.llm.response_headers` includes `content-disposition` and `access-control-allow-origin`. At DEBUG level the log holds the exchange text lengths, the raw reply and the validation error of each case. `verify.llm.max_output_tokens` defaults to 2000.

## Exploit validation

The agent sets `exploit_validated` after code outside the model re-sends the proof and the reflection oracle matches. The re-run sends every PoC request in order, each followed by its control, and confirms when at least one request is positive. It stops after `poc_max_requests` sends (20, controls included), so a 15-request PoC sends its first 10 requests. Every send goes through `ScopedClient`, so the scan rate limit and `Scope.max_requests` apply to each one. Replay soft-404 controls time out after `request_timeout_s`. The agent stays off unless the operator opts in. See [agent safety](agent_safety.md).
