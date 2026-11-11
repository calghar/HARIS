# Security policy

HARIS is pre-1.0. Only the latest minor release receives security fixes.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.7.x | Yes |
| Earlier than 0.7.0 | No |

## Reporting

A vulnerability report for HARIS goes to GitHub private vulnerability reporting for `calghar/HARIS`:

<https://github.com/calghar/HARIS/security/advisories/new>

## Response targets

The times in this section are targets.

- The acknowledgement target is 5 working days.
- The assessment target is 14 days.

## Disclosure

The default coordinated-disclosure window is 90 days from acknowledgement. The reporter and the maintainer may agree on a different window.

## Scope

In scope:

- HARIS code under `src/haris/`
- The web UI and the HTTP API in `src/haris/web/`, including `/api/v1` (`API_V1_PREFIX` in `src/haris/auth/bearer.py`)
- The agent sandbox in `src/haris/agent/` (`DockerRuntime` in `docker_runtime.py`, image name `haris-agent-sandbox` in `settings.py`) and the image file `docker/agent/Dockerfile`
- The CI and release pipeline: `.github/workflows/ci.yml`, `.github/workflows/security.yml`, and `.github/workflows/release.yml`

Out of scope:

- A finding HARIS reports about a third-party target
- A CVE in an external scanner the adapters invoke: Wapiti, SSLyze, Nmap, Nikto, Nuclei, ZAP, garak, and promptfoo (`src/haris/scanners/`)

## Authorised use

`LEGAL_NOTICE.md` states the authorised-use rule. A scan needs the system owner's permission.

## Safe harbour

The safe harbour in this policy is good-faith research on a local install of HARIS.
