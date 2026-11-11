## ADDED Requirements

### Requirement: Authentication on every route
Every route SHALL require an authenticated, active user through a router-level dependency, except `GET /health`, `GET /login`, the `auth` login and OIDC callback routes, and `/static/*`. Unauthenticated requests to `/api/v1/*` MUST return 401 with a JSON body; unauthenticated requests to HTML pages MUST return 303 to `/login?next=<path>`. A test MUST enumerate `app.routes` and fail on any route outside the public allow-list that lacks the dependency.

#### Scenario: Route matrix without a session
- **WHEN** an unauthenticated client sends `<request>`
- **THEN** the response status is `<status>`

#### Examples:
| request | status |
|---------|--------|
| GET /health | 200 |
| GET /login | 200 |
| GET /static/app.css | 200 |
| GET / | 303 |
| GET /scan/abc123 | 303 |
| GET /api/v1/scans | 401 |
| POST /api/v1/scans | 401 |
| GET /api/v1/llm/backends | 401 |
| POST /api/v1/llm/ask | 401 |
| GET /api/v1/llm/conversations | 401 |
| GET /api/v1/templates/status | 401 |
| GET /api/v1/scan-templates/t1 | 401 |
| GET /api/v1/admin/users | 401 |

#### Scenario: Admin routes
- **GIVEN** a logged-in user with role `<role>`
- **WHEN** they send `GET /api/v1/admin/users`
- **THEN** the response status is `<status>`

#### Examples:
| role | status |
|------|--------|
| admin | 200 |
| user | 403 |

#### Scenario: Inactive user
- **GIVEN** a valid session for a user with `is_active` false
- **WHEN** they send `GET /api/v1/scans`
- **THEN** the response status is 401

#### Scenario: Safe next parameter
- **WHEN** login succeeds with `next` `<next>`
- **THEN** the redirect location is `<location>`

#### Examples:
| next | location |
|------|----------|
| /scan/abc | /scan/abc |
| //evil.test/x | / |
| /\evil.test | / |
| https://evil.test/ | / |
| (absent) | / |

### Requirement: Scan ownership
A scan and everything derived from it (status, report, findings, LLM ask, chat and conversations about it) SHALL be visible only to its `owner_user_id` and to users with role `admin`. Other users MUST receive 404. When `HARIS_SHARE_SCANS_ORG_WIDE=true`, every authenticated user MUST be able to read any scan, and a delete by a non-owner, non-admin MUST return 403; the default is false.

#### Scenario: Ownership matrix
- **GIVEN** scan `s1` owned by user `alice` and share setting `<share>`
- **WHEN** `<actor>` sends `<request>`
- **THEN** the response status is `<status>`

#### Examples:
| share | actor | request | status |
|-------|-------|---------|--------|
| false | alice | GET /api/v1/scans/s1 | 200 |
| false | bob | GET /api/v1/scans/s1 | 404 |
| false | admin | GET /api/v1/scans/s1 | 200 |
| false | bob | POST /api/v1/llm/ask with scan_id s1 | 404 |
| false | bob | GET /api/v1/scans/s1/report.json | 404 |
| true | bob | GET /api/v1/scans/s1 | 200 |
| true | bob | DELETE /api/v1/scans/s1 | 403 |
| false | alice | DELETE /api/v1/scans/s1 | 204 |

#### Scenario: Listing is filtered
- **GIVEN** alice owns 2 scans and bob owns 3, share setting false
- **WHEN** bob sends `GET /api/v1/scans`
- **THEN** exactly 3 scans are returned

### Requirement: CSRF on all state-changing requests
Every `POST`, `PUT`, `PATCH` and `DELETE` authenticated by session cookie SHALL carry header `X-CSRF-Token` or form field `csrf_token` equal to the session's CSRF token (constant-time comparison); otherwise the response MUST be 403 and the handler MUST NOT run. Requests authenticated by a Bearer API token MUST be exempt. The session cookie MUST be `HttpOnly`, `SameSite=Lax`, and `Secure` when served over HTTPS.

#### Scenario: CSRF matrix
- **GIVEN** a logged-in session with CSRF token `T`
- **WHEN** it sends `POST /api/v1/scans` with `<csrf>` and `<auth>`
- **THEN** the response status is `<status>`

#### Examples:
| csrf | auth | status |
|------|------|--------|
| header X-CSRF-Token T | session cookie | 202 |
| form field csrf_token T | session cookie | 202 |
| header X-CSRF-Token wrong | session cookie | 403 |
| (absent) | session cookie | 403 |
| (absent) | Bearer token with scans:write | 202 |

### Requirement: Target authorisation for web scans
A web-started scan SHALL be accepted only when the target host passes the SSRF guard of scoped-http and either matches `HARIS_TARGET_ALLOWLIST` or has an `authorized_targets` row for the starting user verified within the last 30 days. Proof MUST use token `haris-verify=<32 hex>` found in a DNS TXT record at `<host>` or `_haris-verify.<host>`, or as the stripped body of `/.well-known/haris-verify.txt` on the exact host fetched through `ScopedClient` (scope, SSRF guard, rate limit; redirects disabled). Proof MUST cover only the exact host. Rejections MUST return 403 (authorisation) or 400 (SSRF) and create no scan.

#### Scenario: Scan start matrix
- **GIVEN** allow-list `<allowlist>` and the starting user's proof state `<proof>`
- **WHEN** the user starts a scan of `<target>`
- **THEN** the response status is `<status>`

#### Examples:
| allowlist | proof | target | status |
|-----------|-------|--------|--------|
| *.example.com | none | https://app.example.com | 202 |
| (absent) | verified for app.example.com 3 days ago | https://app.example.com | 202 |
| (absent) | verified for app.example.com 31 days ago | https://app.example.com | 403 |
| (absent) | verified for example.com | https://app.example.com | 403 |
| (absent) | verified by another user | https://app.example.com | 403 |
| (absent) | none | https://app.example.com | 403 |
| *.example.com | none | http://127.0.0.1:8080 | 400 |
| (absent) | none | http://169.254.169.254/ | 400 |

#### Scenario: File proof does not follow redirects
- **GIVEN** `https://app.example.com/.well-known/haris-verify.txt` returns 302 to `https://attacker.test/token.txt`
- **WHEN** the user requests verification for `app.example.com`
- **THEN** verification fails
- **AND** no request is sent to `attacker.test`

#### Scenario: DNS proof
- **GIVEN** the user's token is `haris-verify=0123456789abcdef0123456789abcdef`
- **AND** `_haris-verify.app.example.com` has that TXT record
- **WHEN** the user requests verification for `app.example.com`
- **THEN** the `authorized_targets` row gets `verified_at` set to now

### Requirement: API tokens
Users SHALL create API tokens of the form `haris_pat_` followed by 43 URL-safe base64 characters, shown once at creation. The server MUST store only the SHA-256 hex digest and a 12-character display prefix, with scopes from `scans:read`, `scans:write`, `targets:write`, `admin`, a required expiry (default 90 days, maximum 365), `last_used_at` and revocation. Tokens MUST be accepted only on `/api/v1/*` via `Authorization: Bearer`; ownership rules MUST apply to the token's user.

#### Scenario: Token matrix
- **GIVEN** a token with scopes `<scopes>` and state `<state>`
- **WHEN** it is sent on `<request>`
- **THEN** the response status is `<status>`

#### Examples:
| scopes | state | request | status |
|--------|-------|---------|--------|
| scans:read | valid | GET /api/v1/scans | 200 |
| scans:read | valid | POST /api/v1/scans | 403 |
| scans:read,scans:write | valid | POST /api/v1/scans | 202 |
| scans:read | expired | GET /api/v1/scans | 401 |
| scans:read | revoked | GET /api/v1/scans | 401 |
| scans:read | valid | GET / | 303 |
| admin | valid, user role user | GET /api/v1/admin/users | 403 |

#### Scenario: Expiry bounds
- **WHEN** a user creates a token with expiry 400 days
- **THEN** the response status is 422

#### Scenario: Plaintext is not stored
- **WHEN** a token is created
- **THEN** the database contains its SHA-256 digest and not the token string

### Requirement: Hashed session tokens
Session tokens SHALL be stored only as the SHA-256 hex digest of the raw token, and lookup MUST hash the presented cookie value. The database migration MUST convert existing plaintext session tokens to digests in place so that sessions created before the upgrade remain valid.

#### Scenario: Migrated session survives
- **GIVEN** a 0.6 database with a session row whose plaintext token is `abc`
- **WHEN** migrations run and the user presents cookie value `abc`
- **THEN** the request is authenticated
- **AND** the stored value is the SHA-256 hex of `abc`
- **AND** no column contains `abc`

### Requirement: Versioned API prefix
All JSON endpoints SHALL be served under `/api/v1` with declared response models. Unprefixed legacy `/api/*` paths MUST return 404.

#### Scenario: Legacy path removed
- **GIVEN** a logged-in user
- **WHEN** they send `GET /api/scans`
- **THEN** the response status is 404
