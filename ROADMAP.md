# Roadmap

Each item is intent, not a commitment, and carries no date. Item numbers refer to `openspec/changes/modernise-0-7/tasks.md`.

## Now

- The 0.7.0 release.
- 2.6 Sandboxed agent (`haris/agent/`), the `agent` stage, and `stage_log`. This is the open deferred line under 2.6.
- 2.7 AI-security module (`ai_security/`, `scanners/garak_scanner.py`, `scanners/promptfoo_scanner.py`).

## Next

- 4.1 LiteLLM replaces the `anthropic` and `openai` SDKs and routes to Bedrock models; model ids and capabilities stay in config; credentials come from the AWS credential chain; no provider key variables remain in code, docs, or CI; regression test: every backend call in `llm/` goes through one LiteLLM wrapper.
- 4.2 Calibrate `verify.llm.abstain_below` on the labelled bench set through the Bedrock backend (the default 0.7 is uncalibrated).
- 4.3 Raise replay coverage for Wapiti findings (SQL injection `error_signature`, XSS `reflection`, `command_injection`, `path_traversal`, `open_redirect`, and `ssrf` stay `unverified` on DVWA); target 95% precision in the replay-verified tier on a meaningful count of verified findings.
- 4.4 Seed the WebGoat crawl so Wapiti reaches the lesson endpoints (the run ends in 3.6 s; recall .571).
- 4.5 Live-test Wapiti 3.3.x `information_disclosure` on DVWA in the sandbox and drop the exclusion only on a clean run.
- 4.6 Bound or skip nuclei phase 2 (531 s on Juice Shop) and sslyze on plain HTTP (`ERROR_NO_CONNECTIVITY` leaves every bench session `incomplete`).

## Later

- 4.7 Align `OWASP_MAPPINGS` with the `cleartext_password_submission` class (reports get A04 only through the Wapiti tag today).
- 4.8 Refute redirect-based catch-all hosts: `baseline.judge` returns early for non-2xx; design D3 describes a 3xx rule.
- 4.9 Classify nikto "This might be interesting" findings (Juice Shop `/ftp` stays a miss) and the remaining nikto and nuclei noise (`gocd-encryption-key` on the `security.txt` prefix route, WebGoat `trace.axd` header).
- 4.10 Give replay its own soft-404 control timeout (it uses the 30 s `policy.timeout_s` today), replay every PoC request (only the first today), and keep the skip note in `errors` on a failed scan (`finish()` can drop it).
- 4.11 Live-verify the unverified surfaces: ZAP end to end, garak and promptfoo output shapes, `action.yml` and the GitLab template, the web UI in a browser, the web agent with real Docker, and XXE out of band.
- 4.12 Run the benchmark with a baseline profile and record the scores with raw artifacts.
