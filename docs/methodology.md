# Methodology

## Assessment Approach

HARIS performs **black-box** security testing. This means:

- No access to source code, internal architecture, or configuration
- All testing is conducted over the network via HTTP/HTTPS
- The tool interacts with the target exactly as an external attacker would
- Findings are based on observable behaviour only

## OWASP Top 10 (2025) Coverage

Findings are mapped to the OWASP Top 10 2025 categories:

### A01: Broken Access Control

- Directory traversal detection (Wapiti)
- CORS misconfiguration checks (misc_checks)
- Exposed admin panels (misc_checks)
- SSRF detection (Wapiti) — folded into A01 in the 2025 edition

### A02: Security Misconfiguration

- Missing security headers (header_checks)
- Directory listing (Wapiti, misc_checks)
- Exposed sensitive files (.env, .git/config, etc.) (misc_checks)
- Server version disclosure (header_checks, Nmap)
- Default/common admin paths (misc_checks)

### A03: Software Supply Chain Failures

- Server software version detection (Nmap)
- Technology stack fingerprinting (Nmap, header_checks)
- Outdated component identification

### A04: Cryptographic Failures

- TLS protocol and cipher analysis (SSLyze, tls_checks)
- Missing HSTS header (header_checks)
- HTTP-to-HTTPS redirect verification (misc_checks)
- Certificate validity and expiry (tls_checks, SSLyze)

### A05: Injection

- SQL injection (Wapiti)
- Cross-site scripting / XSS (Wapiti)
- Command injection (Wapiti)
- CRLF injection (Wapiti)
- XXE injection (Wapiti)

### A06: Insecure Design

- Design-level issues flagged by manual review of scanner output

### A07: Authentication Failures

- Cookie security flags (`cookie_checks`)
- CSRF detection (Wapiti)
- Session management analysis (Wapiti)

### A08: Software or Data Integrity Failures

- Missing Subresource Integrity (`sri_checks`)
- Insecure deserialization indicators (Wapiti)

### A09: Security Logging and Alerting Failures

- Limited black-box detection; noted when error pages reveal logging state

### A10: Mishandling of Exceptional Conditions

- Error page information leakage (info_disclosure)
- Fail-open behaviour detection
- Improper error handling patterns

## Tools Used

| Tool | Focus Area | Integration |
| ------ | ----------- | ------------- |
| Wapiti | Web app vulnerability scanning (SQLi, XSS, injection) | CLI adapter (subprocess) |
| SSLyze | TLS/SSL configuration analysis | CLI adapter (subprocess) |
| Nmap | Port scanning, service detection, recon | CLI adapter (subprocess) |
| Nikto | Web server misconfigurations, outdated software | CLI adapter (subprocess) |
| Nuclei | CVE detection, default credentials, exposed panels, tech fingerprinting | CLI adapter (subprocess, multi-phase) |
| ZAP | Active and passive web scan | CLI adapter, off by default, not in any profile |
| Built-in header_checks | HTTP security headers | ScopedClient |
| Built-in tls_checks | Certificate and TLS basics | Python ssl |
| Built-in misc_checks | CORS, redirects, sensitive paths | ScopedClient |
| Built-in info_disclosure | Error pages, debug endpoints, HTML comments | ScopedClient |
| Built-in cookie_checks | Cookie security flags and configuration | ScopedClient |
| Built-in sri_checks | Subresource Integrity on third-party resources | ScopedClient |
| Built-in cache_checks | Cache-Control on login and account responses | ScopedClient |
| Built-in method_checks | OPTIONS and TRACE | ScopedClient |
| Built-in redirect_checks | Open redirect parameters | ScopedClient |
| Built-in graphql_checks | GraphQL introspection | ScopedClient |
| Built-in openapi_checks | Exposed OpenAPI or Swagger documents | ScopedClient |
| Built-in listing_checks | Directory listing | ScopedClient |
| Built-in dns_checks | CAA, SPF and DMARC | DNS lookup |
| Built-in ai_security | AI endpoints and MCP servers | ScopedClient |

## Safety Controls

The framework enforces multiple safety mechanisms:

1. **Scope enforcement**: Only domains in `allowed_domains` are scanned
2. **Path exclusions**: One entry per line, a plain path (`/logout`) or a path ending in `.*`. `Scope.is_url_in_scope` matches each entry with `re.search` on the URL path, so `/logout` also matches `/logout.php`. Built-in HTTP checks and `ai_security` send requests through `ScopedClient`, which calls that method. Wapiti (`wapiti_exclude_urls`) passes a plain path as `--exclude <origin><path>` and a trailing `.*` as `--exclude <origin><path>*`. Any other pattern is skipped with a warning. Nikto, Nuclei, Nmap and SSLyze leave `excluded_paths` unread. The agent proxy classifier and the guardrail host check match allowed domains only. The proxy's `ScopedClient` applies the target's excluded paths when it sends the request. Patterns are compiled when supplied. An invalid pattern, a pattern longer than 200 characters, or a nested-quantifier or quantified-alternation pattern is rejected. The API returns 422.
3. **Rate limiting**: Configurable requests-per-second limit
4. **Request cap**: Maximum total requests per scan
5. **Authorisation prompt**: the CLI asks for confirmation unless `--yes` is set
6. **Timeouts**: network operations take their timeout from configuration

## Cross-Scanner Intelligence

The recon stage runs the built-in checks and nmap, one at a time, in profile order. It is the only stage that writes `ScanContext`. `header_checks`, `misc_checks` and `info_disclosure` copy `Server`, `X-Powered-By` and `X-AspNet-Version`. nmap copies open ports and product or service names. The scan stage runs the other scanners in parallel and only reads that context.

Nuclei, in the scan stage, uses a three-phase strategy:

- **Phase 1**: Technology fingerprinting via `http/technologies` templates — identifies CMS, WAF, frameworks
- **Phase 2a**: Broad vulnerability scan across 8 template directories (CVEs, exposures, panels, vulnerabilities, default-logins, takeovers, misconfigurations, DAST)
- **Phase 2b**: Tech-targeted scan using Nuclei tags and workflows specific to detected technologies (e.g. WordPress, Django, Jenkins)

Phase 1 is stored as technologies, not as findings. Phase 2 passes `-es info` unless the scanner options set `severity`.
