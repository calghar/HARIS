# HARIS

Orchestrates multiple black-box security scanners against a web target, correlates their findings, and produces a single prioritised report with business-risk context and a remediation checklist.  Optionally uses LLMs to answer questions about scan results and generate remediation artifacts.

## What This Does Differently

Most open-source scanner tools (ZAP, Wapiti, Nuclei) produce isolated reports in their own format.  Teams running three tools against the same target get three separate lists of findings -- many of them duplicates -- with no unified view and no guidance on what to fix first.

HARIS addresses this by:

1. **Cross-tool correlation** -- Findings from all scanners are fingerprinted and merged.  The same XSS reported by Wapiti and Nuclei becomes one finding tagged "confirmed by 2 scanners" instead of two separate entries.

2. **Business-risk translation** -- Every finding includes a plain-language impact statement ("Attackers may execute commands on your server") alongside the technical details.  Reports are readable by product managers, not just security engineers.

3. **Prioritised remediation checklist** -- Instead of per-finding remediation text, the planner groups related fixes, estimates effort (quick win / moderate / significant), and sorts by impact-to-effort ratio.

4. **Scenario-based profiles** -- Rather than "quick" vs "full", profiles map to real workflows: `pre-launch`, `regression`, `compliance`, etc.

5. **LLM-powered analysis** -- Ask questions about a scan ("Explain the top 3 risks for an exec"), generate Jira tickets, draft stakeholder emails, or create CI test cases -- all grounded in the actual report data.

6. **OWASP Top 10 (2025) mapping** -- All findings are mapped to the latest OWASP Top 10 (2025) edition, including the new Supply Chain Failures and Exceptional Conditions categories.

### Scanners (external tools)

| Scanner | What It Tests | Install |
| --------- | --------------- | --------- |
| Wapiti | SQLi, XSS, SSRF, command injection, CRLF, XXE | `pipx install wapiti3` or `uv tool install wapiti3` |
| SSLyze | TLS protocols, cipher suites, certificate chain, Heartbleed/ROBOT | `pipx install sslyze` or `uv tool install sslyze` |
| Nmap | Open ports, service versions, exposed databases | system package manager |
| Nikto | Web server misconfigurations, outdated software, dangerous files | `brew install nikto` or system package manager |
| Nuclei | CVE detection, default credentials, exposed panels (template-based) | `brew install nuclei` or [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |

### Checks (built-in, no external tools)

| Check | What It Tests |
| ------- | --------------- |
| header_checks | 7 security headers (HSTS, CSP, X-Frame-Options, etc.), cookie flags, server banner |
| tls_checks | Certificate expiry, protocol version, cipher strength |
| misc_checks | CORS policy, HTTP->HTTPS redirect, 14 sensitive paths (.env, .git/config, admin panels) |
| info_disclosure | Error page stack traces, debug endpoints, HTML comment leaks, version endpoints |
| cookie_checks | Secure/HttpOnly/SameSite flags, domain scope, expiry, predictable names |

## Setup

```bash
git clone <repo-url> && cd HARIS
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[all]"
```

External tools (Nmap, Nikto, Nuclei, SSLyze, Wapiti) need separate installation — they are invoked as CLI commands via subprocess.  The `quick` and `regression` profiles work without them.

For LLM features, install a provider package and set the API key:

```bash
uv pip install openai          # or: uv pip install anthropic
export OPENAI_API_KEY="sk-..."  # or: export ANTHROPIC_API_KEY="..."
```

## Usage: CLI

```bash
# Quick surface scan
python scripts/run_scan.py --url https://example.com --profile quick --yes

# Full audit
python scripts/run_scan.py --url https://example.com --profile full --yes

# List available profiles and scanners
python scripts/run_scan.py --list-profiles
python scripts/run_scan.py --list-scanners
```

## Usage: LLM Analysis

```bash
# Ask a question about a completed scan
python scripts/run_scan.py llm ask \
  --scan-id 20250222-143025 \
  --question "Explain the top 3 findings for an executive"

# Generate a Jira remediation plan
python scripts/run_scan.py llm remediate --scan-id 20250222-143025 --format jira

# Summarize for developers
python scripts/run_scan.py llm summarize --scan-id 20250222-143025 --audience developer

# Generate CI test cases
python scripts/run_scan.py llm test-cases --scan-id 20250222-143025 --framework pytest

# Use Anthropic instead of OpenAI
python scripts/run_scan.py llm ask --scan-id abc --question "..." --backend anthropic
```

## Usage: Web Dashboard

```bash
python scripts/run_scan.py --web
# Open http://localhost:8000
```

The dashboard provides:

- **Scan History** with findings count, risk posture, and profile for each scan
- **Delete Scan** button to remove scans and their reports from both the UI and database
- **AI-Powered Enrichment** toggle on the scan form — adds attack narratives, chain detection, and smart triage (requires LLM API key)
- **Multi-turn Chat** tab with conversation history, quick-action buttons, and token tracking
- **AI Insights** tab showing attack chains, smart triage table, and enrichment summaries (visible when enrichment is enabled)
- **Structured Actions**: summarize (by audience), explain findings, generate remediation plans (Markdown/Jira/email), CI test cases, and code-level mitigations
- **Remediation Checklist** tab with prioritised steps sorted by impact-to-effort ratio

## Usage: Docker

```bash
docker compose up                      # Web UI on port 8000
docker compose run --rm cli --url https://example.com --profile quick --yes
```

## Scan Profiles

| Profile | Scanners | Duration | Use Case |
| --------- | ---------- | ---------- | ---------- |
| `quick` | Built-in checks only | ~1-3 min | First look, no external tools |
| `pre-launch` | All built-in + Nmap, SSLyze, Wapiti | ~10-30 min | Before production deploy |
| `full` | Everything including Nikto, Nuclei | ~20-30 min | Thorough due-diligence |
| `regression` | header_checks, tls_checks, misc_checks | ~30-60s | CI pipeline gate |
| `compliance` | Built-in + Nmap, SSLyze | ~5-15 min | SOC 2 / PCI-DSS prep |

## Template Management

Scanner templates (Nuclei rules, Nikto databases, etc.) are managed centrally:

```bash
# Update all template sources
python scripts/run_scan.py update-templates

# Update only Nuclei templates
python scripts/run_scan.py update-templates --scanner nuclei

# List current template status
python scripts/run_scan.py update-templates --list
```

Configure sources in `config/default_config.yaml` under `template_sources:`. The web API also exposes `GET /api/templates/status` and `POST /api/templates/update`.

## In-Pipeline LLM Enrichment

Beyond post-scan Q&A, findings can be enriched during the scan:

```bash
python scripts/run_scan.py --url https://example.com --profile quick --yes --llm-enrich
```

This adds attack narratives, business impact, and exploitation complexity to findings above the severity threshold. Configure via `llm.enrichment_enabled: true` in `config/default_config.yaml`. The web dashboard has the same toggle on the New Scan form.

## Configuration

Copy `.env.example` to `.env` for environment variables. See `config/default_config.yaml` for all options.

### Model Routing

Route different LLM tasks to different models for cost optimization:

```yaml
# config/default_config.yaml
llm:
  model_routing:
    enrichment: claude-haiku-4-5       # cheaper model for per-finding enrichment
    attack_chains: claude-sonnet-4-6   # stronger model for chain detection
    triage: claude-haiku-4-5
    summary: claude-haiku-4-5
    chat: claude-sonnet-4-6
```

When no routing is configured, all tasks use the default model.

| Variable | Purpose |
| ---------- | --------- |
| `HARIS_TARGET_URL` | Default scan target |
| `HARIS_PROFILE` | Default scan profile |
| `HARIS_AUTH_HEADER` | Auth header value for target |
| `ANTHROPIC_API_KEY` | Anthropic/Claude LLM backend |
| `OPENAI_API_KEY` | OpenAI LLM backend |
| `OLLAMA_BASE_URL` | Ollama server URL (default: `http://localhost:11434`) |

## Extending

**Add a scanner:** subclass `BaseScanner`, decorate with `@register_scanner`, implement `scan()` and `parse_results()`.  See `docs/integrating_tools.md`.

**Add a check:** same interface, decorate with `@register_check`.  See `docs/writing_checks.md`.

**Add a report format:** subclass `BaseReporter`, implement `generate()`.  Register in `src/reporting/__init__.py`.

**Add an LLM backend:** subclass `BaseLLMBackend`, implement `complete()`.  Add to `BACKEND_REGISTRY` in `src/llm/base.py`.

## Limitations

- Black-box only -- no source code analysis.
- Authentication support is basic (cookie/header).  Complex auth flows (OAuth, MFA) need manual session setup.
- LLM features require an API key and incur costs.  They are entirely optional.
- Findings should be validated by a security professional before acting on them.
- External scanner results depend on those tools being installed and up to date.

## Legal

For authorised testing only.  See [LEGAL_NOTICE.md](LEGAL_NOTICE.md).

## License

MIT.  See [LICENSE](LICENSE).
