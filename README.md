<p align="center">
  <img src="assets/haris_logo.png" alt="HARIS" width="400"><br>
  <em>Black-box web security audit framework. Scan, correlate, prioritise, remediate.</em><br><br>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.13+-blue.svg" alt="Python"></a>
  <a href="https://owasp.org/www-project-top-ten/"><img src="https://img.shields.io/badge/OWASP-Top%2010%202025-red.svg" alt="OWASP"></a>
</p>

Orchestrates security scanners, correlates findings, and writes one prioritised report. LLM analysis is optional.

## What this does

1. **Cross-tool correlation.** Findings that share a fingerprint become one finding. The score combines the scanners that reported it.
2. **Cross-scanner context.** Built-in checks and nmap fill a `ScanContext`. Later scanners read it. Nuclei uses detected technologies in phase 2b.
3. **Business-risk text.** Plain-language impact sits next to the technical finding.
4. **Prioritised remediation.** Fixes are grouped and ordered by impact and effort.
5. **Profiles.** `quick`, `pre-launch`, `full`, `ai-security`, `regression`, `compliance`.
6. **Scan templates.** Named presets with per-scanner overrides, stored and reused from the web UI.
7. **LLM analysis.** Q&A, Jira text, test cases and enrichment, from the scan data.
8. **OWASP Top 10 (2025).** Findings are mapped, including Software Supply Chain Failures and Mishandling of Exceptional Conditions.
9. **Verification.** Replay oracles, an optional LLM verdict, and an opt-in agent. A refuted finding stays in the report. See [`docs/verification.md`](docs/verification.md).

## Scanners

| Scanner | What it tests | Install | Version recorded |
| ------- | ------------- | ------- | ---------------- |
| Wapiti | SQLi, XSS, SSRF, command injection, CRLF, XXE | `pipx install wapiti3` | 3.3 |
| SSLyze | TLS protocols, cipher suites, certificate chain, Heartbleed, ROBOT | `pipx install sslyze` | 6.x |
| Nmap | Open ports, service versions, exposed databases | system package manager | 7.x |
| Nikto | Web server misconfigurations, outdated software, dangerous files | `brew install nikto` | 2.x |
| Nuclei | CVE checks, default credentials, exposed panels, tech fingerprint (phase 1, 2a, 2b) | `brew install nuclei` | 3.x |
| ZAP | Active and passive web scan. Off by default and in no profile. `--scanners zap` | [ZAP download](https://www.zaproxy.org/download/) | 2.16 |
| garak | Injection and leakage probes on a discovered chat route. Runs only with `--ai-active` and `--i-have-authorization` | install the binary | 0.17 |
| promptfoo | Red-team plugins on a discovered chat route. Same flags as garak | install the binary | 0.125 |

The version column is the adapter `version` attribute. `pyproject.toml` floors are `sslyze>=6.3.1` and `wapiti3>=3.3.2`. The Wapiti docstring names 3.3.2. The Nikto docstring names 2.6. Nuclei fixtures in `tests/fixtures/scanners/README.md` are 3.7.1. `garak.yaml` comments 0.17.1 and `promptfoo.yaml` comments 0.125.1. HARIS does not check the tool version at runtime.

Install Wapiti and SSLyze with `pipx`, outside the HARIS environment. `pyproject.toml` records pins `cryptography<47` and `tornado<6.6` and excludes the `scanners` extra from `all` because that extra conflicts with `web`.

## Built-in checks

Fourteen checks. `quick` runs every check except `ai_security`.

| Check | What it tests |
| ----- | ------------- |
| `header_checks` | Six headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy. Also weak CSP or HSTS, a versioned Server banner, and any X-Powered-By header |
| `tls_checks` | Certificate and TLS basics |
| `misc_checks` | CORS, HTTP to HTTPS redirect, 14 sensitive paths |
| `info_disclosure` | Error pages, debug endpoints, HTML comments |
| `cookie_checks` | Session cookie flags, scope, expiry and name |
| `sri_checks` | Subresource Integrity on third-party resources |
| `cache_checks` | Cache-Control on login, account and session-setting responses |
| `method_checks` | OPTIONS advertisement and TRACE |
| `redirect_checks` | Open redirect via common redirect parameters |
| `graphql_checks` | GraphQL introspection |
| `openapi_checks` | Exposed OpenAPI or Swagger documents |
| `listing_checks` | Directory listing |
| `dns_checks` | CAA, SPF and DMARC |
| `ai_security` | AI endpoints and MCP servers. Prompts only with `--ai-active` and `--i-have-authorization`. See [`docs/ai_security.md`](docs/ai_security.md) |

The 14 sensitive paths are `/.env`, `/.git/config`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/wp-login.php`, `/admin`, `/phpmyadmin`, `/server-status`, `/server-info`, `/.DS_Store`, `/crossdomain.xml`, `/elmah.axd` and `/trace.axd`.

## Setup

The console script is `haris`, entry point `haris.cli:main`.

```bash
git clone https://github.com/calghar/HARIS
cd HARIS
uv sync --extra web --extra reporting
uv run haris --help
```

Nmap, Nikto, Nuclei, SSLyze, Wapiti and optional ZAP, garak and promptfoo are separate programs. For LLM features set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. Ollama needs no key. Its client uses `http://localhost:11434` unless the backend is constructed with another base URL.

## Authentication

The web dashboard requires login. On first start an admin account is created from:

```bash
HARIS_ADMIN_EMAIL=admin@example.com
HARIS_ADMIN_PASSWORD=changeme123
HARIS_SECRET_KEY=<random-32-char-string>   # python -c "import secrets; print(secrets.token_hex(32))"
```

Startup creates that admin when both `HARIS_ADMIN_EMAIL` and `HARIS_ADMIN_PASSWORD` are set and the user table is empty. `/auth/setup` answers 404 until `HARIS_SETUP_TOKEN` is set, and once a user exists.

Self-registration uses `HARIS_ALLOWED_EMAIL_DOMAINS`. New accounts need email verification, or an admin activates them when SMTP is off.

Roles are `admin` and `user`. An admin manages users, settings, and any user's scans and templates. A user scans, and views and deletes their own scans, and uses Q&A.

OIDC uses `HARIS_OIDC_ENABLED=true` plus `HARIS_OIDC_ISSUER`, `HARIS_OIDC_CLIENT_ID` and `HARIS_OIDC_CLIENT_SECRET`. See [`docs/authentication.md`](docs/authentication.md).

## Usage

```bash
# CLI. --verify defaults to replay (off, replay, llm).
uv run haris --url https://example.com --profile quick --yes
uv run haris --list-profiles

# Web dashboard. Bind defaults are 127.0.0.1 and port 8000.
uv run haris --web

# Docker
docker compose up
docker compose run --rm cli --url https://example.com --profile quick --yes
make reload

# LLM analysis after a scan
uv run haris llm ask --scan-id <id> --question "Top 3 risks for an exec"
uv run haris llm remediate --scan-id <id> --format jira
uv run haris llm summarize --scan-id <id> --audience developer

# In-pipeline LLM enrichment
uv run haris --url https://example.com --profile quick --yes --llm-enrich

# Scanner template updates
uv run haris update-templates
uv run haris update-templates --scanner nuclei --list
```

## Scan profiles

Estimates are the `estimated_duration` strings on each profile.

| Profile | Scanners | Use |
| ------- | -------- | --- |
| `quick` | The 13 built-in checks other than `ai_security` | First look. 1-3 minutes |
| `pre-launch` | `quick` plus `nmap`, `sslyze`, `wapiti` | Before production. 10-30 minutes |
| `full` | `pre-launch` plus `nikto`, `nuclei` | Full audit. 20-30 minutes. ZAP, garak and promptfoo are absent |
| `ai-security` | `header_checks`, `tls_checks`, `info_disclosure`, `ai_security`, `garak`, `promptfoo` | AI endpoints. 1-10 minutes |
| `regression` | `header_checks`, `tls_checks`, `misc_checks` | CI gate. 30-60 seconds |
| `compliance` | `header_checks`, `tls_checks`, `misc_checks`, `info_disclosure`, `cookie_checks`, `nmap`, `sslyze` | TLS, headers, cookies, disclosure, ports. 5-15 minutes |

## Configuration

Copy `.env.example` to `.env`. The option file is `src/haris/resources/config/default_config.yaml`. Override it with `HARIS_CONFIG` or `./config/default_config.yaml` in the working directory.

| Variable | Purpose |
| -------- | ------- |
| `HARIS_ADMIN_EMAIL` | Bootstrap admin email, used on first start when no users exist |
| `HARIS_ADMIN_PASSWORD` | Bootstrap admin password |
| `HARIS_SECRET_KEY` | Session signing secret |
| `HARIS_TARGET_URL` | Default scan target |
| `HARIS_PROFILE` | Default scan profile |
| `HARIS_AUTH_HEADER` | Auth header value for the target |
| `HARIS_AUTH_COOKIE` | Auth cookie value for the target |
| `HARIS_AUTH_USERNAME` | Auth username for the target |
| `HARIS_AUTH_PASSWORD` | Auth password for the target |
| `ANTHROPIC_API_KEY` | Anthropic LLM backend |
| `OPENAI_API_KEY` | OpenAI LLM backend |
| `HARIS_OIDC_CLIENT_SECRET` | OIDC client secret |
| `HARIS_SMTP_USERNAME` | SMTP username for email verification |
| `HARIS_SMTP_PASSWORD` | SMTP password |

`OLLAMA_BASE_URL` is not read. The Ollama client default is the constructor argument above.

Web server variables. Flags accept `1`, `true` or `yes`, except where noted.

| Variable | Default | Effect |
| -------- | ------- | ------ |
| `HARIS_WEB_VERIFY_DEFAULT` | `replay` | Verification mode for web scans when the request sets none: `off`, `replay` or `llm` |
| `HARIS_TARGET_ALLOWLIST` | empty | Comma-separated host globs that skip ownership proof |
| `HARIS_ALLOW_PRIVATE_TARGETS` | `false` | Allow private and loopback target addresses. Only the value `true` enables it |
| `HARIS_SHARE_SCANS_ORG_WIDE` | `false` | Every user can read all scans. Only owners and admins can change them |
| `HARIS_AGENT_DISABLED` | unset | The value `1` stops the agent from running on any scan |
| `HARIS_MAX_CONCURRENT_SCANS` | `2` | Scans that run at once. At least 1 |
| `HARIS_FORCE_HTTPS` | `false` | Redirect `http://` requests to `https://` |
| `HARIS_ALLOWED_EMAIL_DOMAINS` | `techforpalestine.org` | Comma-separated registration domains. Empty allows any |
| `HARIS_OIDC_ENABLED` | `false` | Turn on OIDC sign-in |
| `HARIS_OIDC_ISSUER`, `HARIS_OIDC_CLIENT_ID` | empty | OIDC provider issuer URL and client ID |
| `HARIS_SMTP_ENABLED` | `false` | Send verification email. Otherwise the link is logged |
| `HARIS_SMTP_HOST`, `HARIS_SMTP_PORT` | `localhost`, `587` | SMTP server |
| `HARIS_SMTP_USE_TLS` | `true` | Any value other than `false` keeps TLS on |
| `HARIS_SMTP_FROM`, `HARIS_SMTP_FROM_NAME` | `noreply@techforpalestine.org`, `HARIS Security Platform` | Sender address and name |
| `HARIS_PUBLIC_URL` | unset | When set, the only base for emailed verification links. When unset, the request base URL is used |
| `HARIS_ALLOWED_HOSTS` | unset | Comma-separated hosts. When set, any other Host header is rejected and www redirect is off. When unset, there is no host check |
| `HARIS_COOKIE_SECURE` | `auto` | `true` forces the Secure flag and `false` omits it. Any other value, including `1` and `yes`, follows the request scheme. Session cookie and CSRF seed cookie |
| `HARIS_SETUP_TOKEN` | unset | `/auth/setup` answers 404 until this is set, and once a user exists. The form field `setup_token` is compared with this value |

## Documentation

- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Methodology: [`docs/methodology.md`](docs/methodology.md)
- Verification: [`docs/verification.md`](docs/verification.md)
- Benchmarks: [`docs/benchmarks.md`](docs/benchmarks.md)
- Agent safety: [`docs/agent_safety.md`](docs/agent_safety.md)
- AI security: [`docs/ai_security.md`](docs/ai_security.md)
- Authentication: [`docs/authentication.md`](docs/authentication.md)
- LLM integration: [`docs/llm_integration.md`](docs/llm_integration.md)
- CI integrations: [`docs/integrations.md`](docs/integrations.md)
- Writing a check: [`docs/writing_checks.md`](docs/writing_checks.md)
- Integrating a tool: [`docs/integrating_tools.md`](docs/integrating_tools.md)

A new scanner subclasses `BaseScanner` and uses `@register_scanner`. A new check uses `@register_check`. A report subclasses `BaseReporter` and implements `generate()`. An LLM backend subclasses `BaseLLMBackend` and implements `complete()`.

## Limitations

- Black-box only. No source code analysis.
- Target auth methods on `AuthConfig` are `none`, `cookie`, `header` and `form`.
- LLM features need an API key and have a cost. They are optional.
- Email verification needs SMTP. Without it, an admin activates accounts.
- A security professional should confirm a finding before anyone acts on it.
- External scanner results depend on those tools being installed.

## Legal

For authorised testing only. See [LEGAL_NOTICE.md](LEGAL_NOTICE.md).

## License

MIT. See [LICENSE](LICENSE).
