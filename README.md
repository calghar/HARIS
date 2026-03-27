<p align="center">
  <img src="assets/haris_logo.png" alt="HARIS" width="400"><br>
  <em>Black-box web security audit framework — scan, correlate, prioritise, remediate.</em><br><br>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.13+-blue.svg" alt="Python"></a>
  <a href="https://owasp.org/www-project-top-ten/"><img src="https://img.shields.io/badge/OWASP-Top%2010%202025-red.svg" alt="OWASP"></a>
</p>

Orchestrates multiple security scanners, correlates findings, and produces a single prioritised report with business-risk context. Optionally uses LLMs for post-scan analysis and remediation planning.

## What This Does Differently

1. **Cross-tool correlation** — findings from all scanners are fingerprinted and merged; duplicates become one confirmed finding.
2. **Cross-scanner intelligence** — technologies, URLs, ports, and headers detected by earlier scanners feed into later ones (e.g. Nuclei targets WordPress-specific templates after Nmap detects WordPress).
3. **Business-risk translation** — plain-language impact statements alongside technical details.
4. **Prioritised remediation** — fixes grouped and sorted by impact-to-effort ratio.
5. **Scenario-based profiles** — `pre-launch`, `regression`, `compliance`, etc.
6. **Reusable scan templates** — named presets with per-scanner overrides, saved and reused from the web UI.
7. **LLM-powered analysis** — Q&A, Jira tickets, test cases, and enrichment grounded in actual scan data.
8. **OWASP Top 10 (2025) mapping** — all findings auto-mapped, including Supply Chain Failures and Exceptional Conditions.

## Scanners

| Scanner | What It Tests | Install |
| ------- | ------------- | ------- |
| Wapiti | SQLi, XSS, SSRF, command injection, CRLF, XXE | `pipx install wapiti3` |
| SSLyze | TLS protocols, cipher suites, certificate chain, Heartbleed/ROBOT | `pipx install sslyze` |
| Nmap | Open ports, service versions, exposed databases | system package manager |
| Nikto | Web server misconfigurations, outdated software, dangerous files | `brew install nikto` |
| Nuclei | CVE detection, default credentials, exposed panels, tech fingerprinting (multi-phase) | `brew install nuclei` |

## Built-in Checks

| Check | What It Tests |
| ----- | ------------- |
| header_checks | 7 security headers (HSTS, CSP, X-Frame-Options, etc.), cookie flags, server banner |
| tls_checks | Certificate expiry, protocol version, cipher strength |
| misc_checks | CORS policy, HTTP→HTTPS redirect, 14 sensitive paths (.env, .git/config, admin panels) |
| info_disclosure | Error page leaks, debug endpoints, HTML comments, version endpoints |
| cookie_checks | Secure/HttpOnly/SameSite flags, domain scope, expiry |

## Setup

```bash
git clone <repo-url> && cd HARIS
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[all]"
```

External tools (Nmap, Nikto, Nuclei, SSLyze, Wapiti) need separate installation — invoked as CLI commands. For LLM features, set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.

## Authentication

The web dashboard requires login. On first start, an admin account is bootstrapped from environment variables:

```bash
HARIS_ADMIN_EMAIL=admin@example.com
HARIS_ADMIN_PASSWORD=changeme123
HARIS_SECRET_KEY=<random-32-char-string>   # generate: python -c "import secrets; print(secrets.token_hex(32))"
```

If those variables are not set, visiting `/auth/setup` creates the first admin account interactively.

**Self-registration** is domain-restricted: only emails matching `auth.allowed_email_domains` in `config/default_config.yaml` can register. New accounts require email verification (or manual admin activation if SMTP is not configured).

**Roles**: `admin` (full access including user management, settings, template deletion) and `user` (scan, view, Q&A).

**OIDC / KeyCloak**: set `auth.oidc.enabled: true` and configure `issuer`, `client_id`, `HARIS_OIDC_CLIENT_SECRET` — see [`docs/authentication.md`](docs/authentication.md).

## Usage

```bash
# CLI
python scripts/run_scan.py --url https://example.com --profile quick --yes
python scripts/run_scan.py --list-profiles

# Web dashboard
python scripts/run_scan.py --web   # http://localhost:8000 — login required

# Docker
docker compose up                  # web UI on port 8000
docker compose run --rm cli --url https://example.com --profile quick --yes
make reload                        # rebuild + restart + stream logs after code changes

# LLM analysis (after a scan completes)
python scripts/run_scan.py llm ask --scan-id <id> --question "Top 3 risks for an exec"
python scripts/run_scan.py llm remediate --scan-id <id> --format jira
python scripts/run_scan.py llm summarize --scan-id <id> --audience developer

# In-pipeline LLM enrichment
python scripts/run_scan.py --url https://example.com --profile quick --yes --llm-enrich

# Scanner template updates
python scripts/run_scan.py update-templates
python scripts/run_scan.py update-templates --scanner nuclei --list
```

## Scan Profiles

| Profile | Scanners | Use Case |
| ------- | -------- | -------- |
| `quick` | Built-in checks only | First look, ~1-3 min |
| `pre-launch` | Built-in + Nmap, SSLyze, Wapiti | Before production deploy, ~10-30 min |
| `full` | Everything including Nikto, Nuclei | Full audit, ~20-30 min |
| `regression` | header_checks, tls_checks, misc_checks | CI gate, ~30-60s |
| `compliance` | Built-in + Nmap, SSLyze | SOC 2 / PCI-DSS prep, ~5-15 min |

## Configuration

Copy `.env.example` to `.env`. See `config/default_config.yaml` for all options.

| Variable | Purpose |
| -------- | ------- |
| `HARIS_ADMIN_EMAIL` | Bootstrap admin email (used on first start if no users exist) |
| `HARIS_ADMIN_PASSWORD` | Bootstrap admin password |
| `HARIS_SECRET_KEY` | Session signing secret — generate a strong random key for production |
| `HARIS_TARGET_URL` | Default scan target |
| `HARIS_PROFILE` | Default scan profile |
| `HARIS_AUTH_HEADER` | Auth header for target |
| `ANTHROPIC_API_KEY` | Anthropic LLM backend |
| `OPENAI_API_KEY` | OpenAI LLM backend |
| `OLLAMA_BASE_URL` | Ollama server (default: `http://localhost:11434`) |
| `HARIS_OIDC_CLIENT_SECRET` | OIDC client secret (KeyCloak / any OIDC provider) |
| `HARIS_SMTP_USERNAME` | SMTP username for email verification |
| `HARIS_SMTP_PASSWORD` | SMTP password |

## Extending

See [`docs/`](docs/) for full developer guides.

- **Scanner**: subclass `BaseScanner`, `@register_scanner` — [`docs/integrating_tools.md`](docs/integrating_tools.md)
- **Custom check**: same interface, `@register_check` — [`docs/writing_checks.md`](docs/writing_checks.md)
- **Report format**: subclass `BaseReporter`, implement `generate()`
- **LLM backend**: subclass `BaseLLMBackend`, implement `complete()`
- **Architecture & templates**: [`docs/architecture.md`](docs/architecture.md)
- **LLM integration**: [`docs/llm_integration.md`](docs/llm_integration.md)
- **Authentication & users**: [`docs/authentication.md`](docs/authentication.md)

## Limitations

- Black-box only — no source code analysis.
- Target auth: cookie/header injection only; complex flows (OAuth, MFA, OTP) need manual pre-auth.
- LLM features require an API key and incur costs — entirely optional.
- Email verification requires SMTP config; without it, admins activate accounts manually.
- Validate findings with a security professional before acting on them.
- External scanner results depend on those tools being installed and up to date.

## Legal

For authorised testing only. See [LEGAL_NOTICE.md](LEGAL_NOTICE.md).

## License

MIT. See [LICENSE](LICENSE).
