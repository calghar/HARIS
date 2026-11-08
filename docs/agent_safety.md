# Agent safety

This note describes `haris.agent` in the `ws/agent` worktree on 2026-11-08. Container fields were read from `docker inspect` in `tests/test_agent_docker.py` on that date. Proxy, guardrail and tier claims were checked by the tests named below.

The validator stays off unless the operator opts in. A finding becomes `exploit_validated` only after code outside the model re-sends the proof and a reflection oracle matches.

## Activation

The CLI binds a policy when both `--agent` and `--i-have-authorization` are present. `--agent` alone makes `bind_cli` return exit code 3 before `ScanRunner` starts, so the process makes no target request. `HARIS_AGENT_DISABLED=1` leaves the policy unset. Web scans have no call site in this tree. `policy_for_web(is_admin, target_authorised, output_dir)` returns a policy only for an admin whose target authorisation is verified. The web layer has to call `bind_policy` with that result.

## Boundaries

The model output is untrusted. Each tool name must be one of `http_request`, `run_python`, `write_file`, `read_file`, `submit_poc`. Arguments are matched against the denylist in `guardrails.py`. Removing a denylist entry fails `test_denylist_entries_are_the_contract`. `run_python` also rejects an AST that imports `subprocess`, `socket`, `pty` or `ctypes`, or that calls `exec`, `eval`, `compile`, `__import__`, `os.system` or `os.popen`. File paths must stay under `/work`.

Target bytes are untrusted. The coordinator wraps the finding text and each tool result with `haris.llm.redaction.fence`. The system prompt starts with `DATA_CLAUSE`, which states that the fence is data. `test_hostile_page_cannot_send_the_model_off_scope` serves a page that asks for a request to `evil.test`, for the guardrails to be disabled, and for every finding to be marked confirmed. The guardrail blocks the out-of-scope call and the audit log records the block. The tier stays `replay_verified`.

The sandbox is untrusted. `DockerRuntime` starts one container per job from `container_argv`: a read-only root, tmpfs on `/work` and `/tmp`, `--cap-drop ALL`, `no-new-privileges`, a pids limit of 128, 512 MiB of memory, 1 CPU, user `65534:65534`, and no `-v`, `--volume`, `--mount` or `--privileged`. The network mode is a named internal network. The process environment is set in the argv and is not copied from the host, so a configured LLM API key is absent. `HTTP_PROXY` and `HTTPS_PROXY` are `http://job:<token>@proxy:8080`. That sandbox environment is the only place the job token is kept. The audit log replaces the token with `[REDACTED]` before it writes a line. The tunnel environment and the report do not receive it. The integration test on 2026-11-08 recorded User `65534:65534`, ReadonlyRootfs true, CapDrop `['ALL']`, SecurityOpt `['no-new-privileges']`, PidsLimit 128, Memory 536870912, NanoCpus 1000000000, Privileged false, NetworkMode `haris-agent-job-job-itest`, Binds none and Mounts empty. HostConfig.Tmpfs was `/work` `rw,size=64m` and `/tmp` `rw,size=16m`. A TCP connect from that container to `10.255.255.1:9` printed no `connected` line.

The tunnel is a byte pipe. The sandbox joins an internal Docker network. The only egress name on that network is `proxy`, an alias of a sidecar that runs `docker/agent/tunnel.py`. The sidecar is also attached to a second network, and it is the only container started with `host.docker.internal:host-gateway`. It copies TCP to the host `ScopeProxy`. It does not parse HTTP and it does not see the job token. The host proxy listens on `127.0.0.1`. On this Colima host, checked 2026-11-08, a container connection to `host.docker.internal` was accepted by a socket bound to `127.0.0.1` (peer address `127.0.0.1`). `192.168.5.2`, the address the container uses for that name, is not assigned on the host. The vmnet bridge `192.168.105.1` did not receive the same connection. Loopback is the narrow bind that the tunnel can still reach. Other processes on the host can open `127.0.0.1`, so each job also requires `Proxy-Authorization: Basic` with `base64(job:<32-byte token>)`. A missing or wrong header is status 407, an audit line with reason `auth`, and no upstream request. A matching header is compared by hashing both sides and calling `hmac.compare_digest`. The host proxy then classifies the request and, when the decision is forward, sends it with `ScopedClient`, which applies scope, SSRF, the rate limit, the request cap and per-hop redirect checks from `haris.net`.

The validator is outside the model. `apply_validation` calls `Verification.advance` only after `reexecute` gets a positive reflection oracle on a fresh marker. The review-model reply is written to the audit log and is ignored for the tier. A failed re-execution stores `agent_annotation` and leaves the tier where it was.

## Proxy rules

`classify_request` rejects `PUT`, `PATCH` and `DELETE`. It rejects `POST` unless `allow_unsafe` is set. It rejects a metadata host or literal, an out-of-scope host, and a body or URL that matches the destructive SQL or long-sleep pattern. `ScopedClient` repeats the scope, SSRF, rate and cap checks, and records a redirect whose next hop is out of scope. A proxy body of `rejected: scope` or `rejected: ssrf` kills the job on the first occurrence. Any other guardrail hit kills the job on the third. Budget kills use the reasons `tool_calls`, `tokens` and `wall_clock`. Each kill appends a line to `<output>/agent/<job_id>/audit.jsonl`. String fields in that file pass through `haris.llm.redaction.redact`, then the job token is replaced with `[REDACTED]`.

## Gaps

Live requests in the tests use HTTP. There is no `CONNECT` handler and no per-job TLS certificate. An `https://` URL is classified and is not dialed.

A fault in the sidecar or in the Docker daemon sits outside the proxy. The sidecar can open TCP to the host gateway. The fixture in the integration test listens on `127.0.0.1` of the host, so the sidecar reaches it only by handing the bytes to the host proxy, which then connects after classification.

The AST check on `run_python` is a filter. Isolation is the container: uid 65534, the limits above, and sockets that leave only through the `proxy` alias. A payload that the filter accepts still runs inside those limits.

The dollar cap is `LLMBudget` on a `ProviderBackend` whose price table contains the model. An unknown price is stored as zero cost, so the dollar cap does not trip. `JobBudget` still stops the job when `max_tokens` is exceeded.

`Finding.to_dict` omits `raw_data`, so `agent_annotation` is absent from the JSON report until reporting reads that field. The stage list is a private attribute on the session object and is not a field of `ScanSession`.

Re-execution is implemented for the reflection oracle. A proof for another class is stored as an annotation and the tier stays put.

The image name in `agent.yaml` is `haris-agent-sandbox`. The integration test builds `haris-agent-sandbox:local` with `docker build --pull=false -t haris-agent-sandbox:local docker/agent`. `DockerRuntime` then pins the id from `docker image inspect`. A CLI job fails when that configured tag is missing.
