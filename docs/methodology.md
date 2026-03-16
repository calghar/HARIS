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

- Cookie security flags (header_checks)
- CSRF detection (Wapiti)
- Session management analysis (Wapiti)

### A08: Software or Data Integrity Failures

- Missing Subresource Integrity (future check)
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
| Nuclei | CVE detection, default credentials, exposed panels | CLI adapter (subprocess) |
| Built-in header_checks | HTTP security headers | Python requests |
| Built-in tls_checks | Certificate and TLS basics | Python ssl |
| Built-in misc_checks | CORS, redirects, sensitive paths | Python requests |
| Built-in info_disclosure | Error pages, debug endpoints, HTML comments | Python requests |
| Built-in cookie_checks | Cookie security flags and configuration | Python requests |

## Safety Controls

The framework enforces multiple safety mechanisms:

1. **Scope enforcement**: Only domains in `allowed_domains` are scanned
2. **Path exclusions**: Sensitive paths can be excluded via regex patterns
3. **Rate limiting**: Configurable requests-per-second limit
4. **Request cap**: Maximum total requests per scan
5. **Authorisation prompt**: CLI requires explicit user confirmation
6. **Non-destructive payloads**: Test payloads demonstrate vulnerabilities without data extraction
7. **Timeouts**: All network operations have configurable timeouts
