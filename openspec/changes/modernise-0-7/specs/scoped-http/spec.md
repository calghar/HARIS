## ADDED Requirements

### Requirement: Single choke point for in-process traffic
All HTTP traffic from built-in checks, the soft-404 baseline, the replay verifier, the AI-security module and target-ownership proof SHALL be sent through one `ScopedClient` instance per scan. Modules outside `haris.net` MUST NOT import `requests`, `httpx` or `urllib3` directly; the lint gate MUST fail on such an import.

#### Scenario: Direct requests import is rejected
- **GIVEN** a module `haris/checks/new_check.py` containing `import requests`
- **WHEN** the lint gate runs
- **THEN** it fails naming `haris/checks/new_check.py`

#### Scenario: Built-in checks share one client
- **GIVEN** a scan running `header_checks`, `misc_checks` and `info_disclosure`
- **WHEN** the scan completes
- **THEN** every request those checks sent appears in the one `RequestLog` of the scan

### Requirement: Scope enforcement per request and per redirect hop
`ScopedClient` SHALL reject before sending any request whose scheme is not `http` or `https`, whose URL fails `Scope.is_url_in_scope`, or whose method is not in `Scope.allowed_methods`, raising `ScopeViolation`. Redirects MUST be followed manually only when `Scope.follow_redirects` is true, for at most `Scope.max_redirect_depth` hops, and each hop MUST pass the same scope, SSRF, rate-limit and request-cap checks; a failing hop ends the chain, returns the last in-scope response and sets `redirect_blocked`.

#### Scenario: Redirect hop matrix
- **GIVEN** scope `allowed_domains` `example.com`, `excluded_paths` `^/admin`, `max_redirect_depth` 2
- **WHEN** `GET https://example.com/start` redirects through `<chain>`
- **THEN** the number of requests sent is `<sent>`
- **AND** `redirect_blocked` is `<blocked>`

#### Examples:
| chain | sent | blocked |
|-------|------|---------|
| https://www.example.com/a | 2 | false |
| https://evil.test/a | 1 | true |
| https://example.com/admin/x | 1 | true |
| ftp://example.com/a | 1 | true |
| https://example.com/a then https://example.com/b then https://example.com/c | 3 | true |
| http://169.254.169.254/latest/meta-data | 1 | true |

#### Scenario: Method outside scope
- **GIVEN** `Scope.allowed_methods` is `GET`, `HEAD`, `OPTIONS`
- **WHEN** a check calls `ScopedClient.request("POST", "https://example.com/login")`
- **THEN** `ScopeViolation` is raised
- **AND** no request is sent

### Requirement: SSRF guard with pinned resolution
`ScopedClient` SHALL resolve each (host, port) once per scan, reject the request with `SSRFBlocked` when any resolved address is in a blocked class, and connect only to a vetted address while sending the original `Host` header and validating TLS against the original hostname. Blocked classes: unspecified, loopback, RFC1918, CGNAT 100.64.0.0/10, link-local, IPv6 ULA fc00::/7, multicast, reserved, and IPv4 embedded in IPv4-mapped, NAT64 64:ff9b::/96 or 6to4 2002::/16 addresses. Cloud metadata addresses (169.254.169.254, fd00:ec2::254, 100.100.100.200) and host `metadata.google.internal` MUST be blocked even when `allow_private` is true. All other classes MUST be allowed when `allow_private` is true.

#### Scenario: Address class matrix
- **GIVEN** host `t.example` resolves to `<ip>`
- **WHEN** a request to `https://t.example/` is made with `allow_private` `<allow_private>`
- **THEN** the outcome is `<outcome>`

#### Examples:
| ip | allow_private | outcome |
|----|---------------|---------|
| 93.184.216.34 | false | sent |
| 127.0.0.1 | false | SSRFBlocked |
| 127.0.0.1 | true | sent |
| 10.1.2.3 | false | SSRFBlocked |
| 172.16.0.1 | false | SSRFBlocked |
| 192.168.1.1 | false | SSRFBlocked |
| 100.64.0.1 | false | SSRFBlocked |
| 169.254.10.10 | false | SSRFBlocked |
| 169.254.169.254 | true | SSRFBlocked |
| 100.100.100.200 | true | SSRFBlocked |
| 0.0.0.0 | false | SSRFBlocked |
| ::1 | false | SSRFBlocked |
| fe80::1 | false | SSRFBlocked |
| fd12:3456::1 | false | SSRFBlocked |
| fd00:ec2::254 | true | SSRFBlocked |
| ::ffff:127.0.0.1 | false | SSRFBlocked |
| 64:ff9b::a01:203 | false | SSRFBlocked |
| 2002:c0a8:101::1 | false | SSRFBlocked |
| 2606:2800:220:1:248:1893:25c8:1946 | false | sent |

#### Scenario: Mixed resolution is rejected
- **GIVEN** host `t.example` resolves to `93.184.216.34` and `10.0.0.5`
- **WHEN** a request to `https://t.example/` is made with `allow_private` false
- **THEN** `SSRFBlocked` is raised

#### Scenario: DNS rebinding after first resolution
- **GIVEN** host `t.example` resolved to `93.184.216.34` at the first request
- **AND** the resolver now answers `127.0.0.1`
- **WHEN** a second request to `https://t.example/x` is made in the same scan
- **THEN** the connection goes to `93.184.216.34`

### Requirement: Rate limit and request cap
`ScopedClient` SHALL pace requests with a token bucket of capacity `max(1, ceil(Scope.rate_limit_rps))` refilled at `Scope.rate_limit_rps`, shared across all callers in the scan, and SHALL raise `RequestBudgetExceeded` for the request that would exceed `Scope.max_requests`, without sending it. Redirect hops and retries MUST count toward both limits.

#### Scenario: Request cap
- **GIVEN** `Scope.max_requests` is 5
- **WHEN** checks attempt 8 requests
- **THEN** 5 requests are sent
- **AND** the sixth attempt raises `RequestBudgetExceeded`
- **AND** the scan records an error naming the cap

#### Scenario: Rate limit
- **GIVEN** `Scope.rate_limit_rps` is 2 and an injected clock
- **WHEN** 10 requests are issued at once
- **THEN** the tenth request is sent no earlier than 4.0 seconds after the first

### Requirement: Retry, backoff and 429 handling
`ScopedClient` SHALL retry at most 2 times on connection errors and status 502, 503 or 504 with exponential backoff starting at 0.5 s plus jitter. On status 429 it MUST wait for `Retry-After` capped at 60 s, halve the bucket refill rate for the rest of the scan, and stop after 3 attempts, returning the last 429 response.

#### Scenario: Retry outcomes
- **WHEN** the target answers `<responses>` to one logical request
- **THEN** `<sent>` requests are sent and the returned status is `<status>`

#### Examples:
| responses | sent | status |
|-----------|------|--------|
| 200 | 1 | 200 |
| 503, 200 | 2 | 200 |
| 503, 503, 503 | 3 | 503 |
| 404 | 1 | 404 |
| 429 (Retry-After 1), 200 | 2 | 200 |
| 429, 429, 429 | 3 | 429 |

#### Scenario: Rate halves after 429
- **GIVEN** `Scope.rate_limit_rps` is 4
- **WHEN** the target answers one request with 429
- **THEN** the bucket refill rate is 2 for the remaining requests

### Requirement: Redacted request log
Each sent request SHALL produce a `RequestLog` entry with `request_id`, method, URL, status, elapsed time, and request and response headers and body excerpts of at most 8 KiB. Header values for `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and any header name matching `(?i)(token|secret|api[-_]?key|auth|session)` MUST be replaced with `[REDACTED]` in the log, in evidence and in application logs.

#### Scenario: Header redaction
- **GIVEN** target auth header `Authorization: Bearer abc123`
- **WHEN** a request is sent and its response sets `Set-Cookie: sid=xyz`
- **THEN** the log entry shows `Authorization: [REDACTED]` and `Set-Cookie: [REDACTED]`
- **AND** the strings `abc123` and `xyz` appear nowhere in the log, the JSON report or the application log output

### Requirement: Private-target override
`NetworkPolicy.allow_private` SHALL default to false. The CLI MUST set it to true only when `--allow-private` is given. A web-started scan MUST set it to true only when the server environment has `HARIS_ALLOW_PRIVATE_TARGETS=true`, and MUST ignore any request field that tries to set it.

#### Scenario: Override sources
- **GIVEN** the scan is started from `<source>` with `<input>`
- **WHEN** the target resolves to `10.0.0.5`
- **THEN** the outcome is `<outcome>`

#### Examples:
| source | input | outcome |
|--------|-------|---------|
| cli | (absent) | SSRFBlocked |
| cli | --allow-private | sent |
| web | form field allow_private=true | SSRFBlocked |
| web | env HARIS_ALLOW_PRIVATE_TARGETS=true | sent |

### Requirement: External tool pre-flight and rate split
Before an external scanner starts, the target host SHALL pass the scheme, scope and SSRF checks of `ScopedClient`; on failure the scanner MUST NOT start and the scan MUST record an error. Concurrently running external tools MUST each receive a rate of `Scope.rate_limit_rps / n_concurrent` (minimum 1) passed through the tool's rate flag (nuclei `-rl` rounded down to a whole number, nmap `--max-rate`, nikto `-Pause` as the reciprocal in seconds), placed after any `extra_args` so they cannot raise it, with redirects governed by each tool's own setting.

#### Scenario: Pre-flight blocks private target
- **GIVEN** the target resolves to `192.168.1.10` and `allow_private` is false
- **WHEN** the scan starts with scanners `nuclei` and `nikto`
- **THEN** neither binary is executed
- **AND** the scan state is `failed`

#### Scenario: Rate split
- **GIVEN** `Scope.rate_limit_rps` is 10 and `--parallel 2`
- **WHEN** a scan runs `nmap`, `nuclei` and `nikto`, with `nmap` alone in the first stage
- **THEN** nmap's argv contains `--max-rate 10`
- **AND** nuclei's argv contains `-rl 5`
- **AND** nikto's argv contains `-Pause 0.2`
