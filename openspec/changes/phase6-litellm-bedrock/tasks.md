Ids in brackets map to `modernise-0-7/tasks.md` section 4; tick both files when a task is done. Land tasks in order. Run the full gate (ruff, format, mypy, `uv lock --check`, pytest) after every numbered section.

## 1. Barrier and environment

- [x] 1.1 Added `pytest-bdd` to the dev group, ran `uv lock`, wrote step definitions as stubs, ran `uv run pytest tests/features`, and recorded the result: the preserved scenarios of `modernise-0-7` pass, every new scenario of this change fails (feature files already generated from `modernise-0-7` and `phase6-litellm-bedrock`)
- [x] 1.2 Verified the runtime on the new machine: `podman --version`, `podman compose` (or the `docker` shim) can start `bench/compose.yaml`, rootless exec, `--pids-limit`, tmpfs and the agent sandbox image build; recorded the result in `tmp/phase6-env.md`; wherever Podman differs, fixed `docker_runtime.py` or the docs rather than skipping a task
- [x] 1.3 Moved the benchmark images to `ghcr.io` where an official image exists (check each of Juice Shop, DVWA, WebGoat, MariaDB), pinned each by digest, kept Docker Hub only where no ghcr image exists, and noted the choice in `bench/README.md`

## 2. LLM backend [4.1]

- [x] 2.1 Declared the `llm` extra with `litellm==<pin>` (a release at least 7 days old, checked on PyPI; new transitive packages held to the same age), removed `anthropic` and `openai` from the main group, ran `uv lock`, added `scripts/check_litellm.py` (deny-list, `==` form, hashes) and called it from CI and the pre-release gate; Dependabot ignores `litellm`
- [x] 2.2 Added `llm/litellm_backend.py` (`LiteLLMBackend`, `validate_model`, `LLMConfigError`, `scrub`, `table_cost`) with tests for: call parameters, gateway call, direct Bedrock call, secret in an error, structured output, unsupported format, retry sequence
- [x] 2.3 Replaced `settings.py`, `llm_models.yaml` and `catalog.py` contents per design D1 and D5; added `LLMConfig.api_base` and `api_key_env`; set the `backend` default; regression test: `runtime`, `budget`, `pricing`, `redaction` and `limits` still load
- [x] 2.4 Wired the config price first, then `table_cost`, into `LLMBudget`; regression test: existing `test_llm_budget.py` passes unchanged; added the price-order examples
- [x] 2.5 Updated `create_backend`, `BACKEND_REGISTRY`, `get_available_backends`, `get_default_backend_name`, `ModelRouter`, `core/runner.py` and `cli.py` (flags, help text, exit 3 on `LLMConfigError`); regression tests: `test_llm.py`, `test_router.py` pass with backend names changed; added the legacy-name and model-string examples
- [x] 2.6 Updated `web/llm_support.py` (400 on `LLMConfigError`, scrubbed log), `web/routers/llm_chat.py`, `pages.py`, `settings.html`, the template form and `scan_new` scripts; regression test: `test_web_llm.py` passes with names changed; added the endpoint-display and availability examples
- [x] 2.7 Added migration `0009_llm_backend_names.py` with a one-way rollback; tests for every example and the idempotent run; added the backup warning to `docs/upgrading.md` (create it if missing)
- [x] 2.8 Removed provider key names from `README.md`, `docs/llm_integration.md`, `default_config.yaml` comments, CI and compose files; added the old-to-new table, the gateway example, the Bedrock example, the Ollama example and the container note; CHANGELOG entry marked BREAKING; regression test: the source grep for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `AWS_`
- [ ] 2.9 Ran a live call through the gateway and a direct Bedrock call, and recorded the model strings and outputs under `bench/results/`
- [ ] 2.10 Calibrated `verify.llm.abstain_below` with `bench/calibrate_abstain.py` on the labelled set through the live backend, committed the raw artifacts, set the default per the spec, and cited them in `docs/verification.md` [4.2]

## 3. Verification

- [x] 3.1 Agent PoC re-execution of every request with the `verify.poc_max_requests` cap (default 20) and the client rate limit, control timeout from `verify.request_timeout_s`, and skip notes kept on a failed scan; regression test: existing replay tests and `test_db_scope.py` pass [4.10]
- [x] 3.2 Redirect catch-all rule in `baseline.judge` and replay of external findings; regression test: existing baseline tests pass [4.8]
- [x] 3.3 Oracles and `vuln_classes.yaml` keys for `path_traversal`, `open_redirect` and `command_injection` (delay-only payloads); `ssrf` and `xxe` stay without an oracle; regression test: the existing oracle matrix passes [4.3]
- [ ] 3.4 Ran DVWA with replay on; recorded `verified_precision` and the count of `replay_verified` findings (at least 0.95 over at least 10); iterated on oracles, not on the target list, until it holds [4.3]
- [ ] 3.5 Nikto `interesting_path` class and `info` severity (checked against the nikto severity map), and the two named noise items; regression test: existing nikto parser tests pass [4.9]

## 4. Scanners and external tools

- [x] 4.1 `partial` and `skipped` statuses in `ScannerResult.metadata`, `scanner_status`, `Engine._final_state`, reports and the DB round trip; regression test: existing exit-code matrix and `scanner_status` tests pass
- [ ] 4.2 `scanners.nuclei.phase2_timeout_s` (default 300) with process-group kill and kept findings; ran Juice Shop and recorded the phase 2 time [4.6]
- [x] 4.3 sslyze skipped when the target is HTTP and no TLS port was found; regression test: HTTPS target still runs sslyze [4.6]
- [x] 4.4 Per-tool address binding or blocking network for nuclei, nmap, nikto, sslyze and Wapiti after reading each `--help`; rebinding test per tool; a tool with neither does not start; updated the Known limits note in `docs/agent_safety.md` and `SECURITY.md` [4.13]
- [ ] 4.5 Seeded the WebGoat crawl so Wapiti reaches the lesson endpoints; recorded recall before and after [4.4]
- [ ] 4.6 Live-tested Wapiti `information_disclosure` on DVWA in the sandbox; dropped the exclusion only on a clean run [4.5]
- [x] 4.7 Passed `ScanContext.tool_rate_rps` to nuclei `-rl`, nmap `--max-rate` and nikto `-Pause` per the existing "External tool pre-flight and rate split" requirement of `modernise-0-7`; replaced the pending entry of `Rate split` in `tests/bdd/maps/scoped-http.preserved.yaml` with its tests; regression test: existing `test_engine_pipeline.py` rate tests pass with nmap expectations corrected to the scenario

## 5. Classification

- [x] 5.1 OWASP category from the canonical class, `cleartext_password_submission` to A04 with CWE-319, the `unmapped` list and its coverage test [4.7]

## 6. Live verification and benchmark

- [ ] 6.1 Live-verified ZAP end to end, garak and promptfoo output shapes, `action.yml` and the GitLab template, the web UI in a browser, the web agent with the container runtime, and XXE out of band; recorded each result [4.11]
- [ ] 6.2 Ran the benchmark with a baseline profile and recorded the scores with raw artifacts [4.12]

## 7. Structural refactors (after sections 2 to 6 are merged and green)

- [ ] 7.1 Explicit built-in maps for checks, scanners and oracles; second scanner registry and trigger-only imports removed [4.14]
- [ ] 7.2 `cli.py` split into parser, handlers and scan orchestration [4.15]
- [ ] 7.3 Nuclei selection and argv construction in a data-only module [4.16]
- [ ] 7.4 `bench/run.py` split into target preparation and command execution [4.17]
- [ ] 7.5 Regenerated features with `openspec-bdd generate`, ran `openspec validate --all --strict`, archived this change, and bumped the version per the release task 3.5 of `modernise-0-7`
