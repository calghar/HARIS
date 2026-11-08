## ADDED Requirements

### Requirement: Stable fingerprint
Every finding SHALL carry a `fingerprint` equal to the lowercase hex SHA-256 of `v1`, the CWE, the canonical `vuln_class`, the normalised URL, the upper-cased method and the parameter joined by `\x1f`, and a `finding_id` equal to the first 16 characters of the fingerprint. The CWE input MUST be the class `primary_cwe` when the class is mapped (cwe.mitre.org ids, e.g. CWE-79), else the finding's `cwe_id`, else `CWE-NONE`. The fingerprint MUST NOT depend on the verification tier, so a finding keeps its fingerprint as tier `unverified`, `replay_verified`, `exploit_validated` or `refuted`.

#### Scenario: Volatile query values do not change identity
- **GIVEN** two findings of class `xss_reflected` on parameter `q` with method `GET`
- **WHEN** their URLs are `<url_a>` and `<url_b>` with base URL `https://example.com`
- **THEN** their fingerprints are `<relation>`

#### Examples:
| url_a | url_b | relation |
|-------|-------|----------|
| https://example.com/search?q=1&t=123 | https://example.com/search?t=999&q=abc | equal |
| https://EXAMPLE.com:443/search/?q=1 | https://example.com/search?q=2 | equal |
| /search?q=1 | https://example.com/search?q=1 | equal |
| https://example.com/search?q=1#frag | https://example.com/search?q=1 | equal |
| https://example.com/search?q=1 | https://example.com/find?q=1 | different |
| https://example.com/search?q=1 | http://example.com/search?q=1 | different |
| https://example.com/search?q=1 | https://example.com/search?q=1&debug=1 | different |

#### Scenario: Fingerprint is unchanged by tier
- **GIVEN** a finding with fingerprint `F` and tier `unverified`
- **WHEN** the verification stage sets its tier to `<tier>`
- **THEN** its fingerprint is still `F`
- **AND** its `finding_id` is still the first 16 characters of `F`

#### Examples:
| tier |
|------|
| replay_verified |
| exploit_validated |
| refuted |

#### Scenario: Host-granularity classes ignore path
- **GIVEN** class `missing_header` has granularity `host`
- **WHEN** a finding for header `strict-transport-security` is raised on `https://example.com/a` and another on `https://example.com/b/c`
- **THEN** both findings have the same fingerprint

### Requirement: Correlation by canonical class without mutation
The correlator SHALL group findings by `fingerprint`, choose as canonical a deep copy of the member ranked highest by tier (`exploit_validated` > `replay_verified` > `unverified` > `refuted`), then severity, then `confidence_score`, and set the correlated severity to the maximum severity in the group. The correlator MUST NOT modify any input finding.

#### Scenario: Two scanners with different titles merge
- **GIVEN** Wapiti reports "Cross Site Scripting" with relative URL `/search?q=x` and parameter `q`
- **AND** Nuclei reports "Reflected XSS" on `https://example.com/search?q=y` with parameter `q`
- **AND** both map to class `xss_reflected`
- **WHEN** the correlator runs with base URL `https://example.com`
- **THEN** exactly one correlated finding exists with sources from `wapiti` and `nuclei`

#### Scenario: Inputs are not mutated
- **GIVEN** two findings with the same fingerprint, both with `confidence` `tentative`
- **WHEN** the correlator runs
- **THEN** both input findings still have `confidence` `tentative`
- **AND** the correlated canonical is a different object from both inputs

#### Scenario: Unmapped findings from different scanners stay separate
- **GIVEN** Nikto and Nuclei each report an unmapped finding titled "Interesting header" on the same URL
- **WHEN** the correlator runs
- **THEN** two correlated findings exist with classes `unclassified:nikto:interesting-header` and `unclassified:nuclei:interesting-header`

### Requirement: Numeric confidence and consensus
Every finding SHALL carry `confidence_score` in [0.0, 1.0] and an enum `confidence` derived from it (`confirmed` when >= 0.9, `firm` when >= 0.6, else `tentative`). A correlated finding's score MUST be `min(0.95, 1 - product(1 - c_i))` over the highest prior per distinct scanner, then floored by tier: `unverified` keeps the consensus value, `replay_verified` takes `max(score, 0.9)`, `exploit_validated` takes `1.0`, `refuted` takes `0.0`.

#### Scenario: Consensus and tier floors
- **GIVEN** a correlated finding whose per-scanner priors are `<priors>`
- **WHEN** its tier is `<tier>`
- **THEN** its `confidence_score` is `<score>`
- **AND** its `confidence` is `<enum>`

#### Examples:
| priors | tier | score | enum |
|--------|------|-------|------|
| 0.5 | unverified | 0.5 | tentative |
| 0.5,0.5 | unverified | 0.75 | firm |
| 0.8,0.9,0.9 | unverified | 0.95 | confirmed |
| 0.5 | replay_verified | 0.9 | confirmed |
| 0.5 | exploit_validated | 1.0 | confirmed |
| 0.8,0.9 | refuted | 0.0 | tentative |

#### Scenario: LLM verdict adjusts score but not tier
- **GIVEN** an `unverified` finding with consensus score 0.5
- **WHEN** a valid LLM assessment returns `likely_fp` with confidence 1.0
- **THEN** its `confidence_score` is 0.2
- **AND** its tier is still `unverified`

### Requirement: Confidence-weighted risk over correlated findings
Risk posture SHALL be computed from `session.correlated` as the sum over findings of severity weight (critical 25, high 10, medium 3, low 1, info 0) times `confidence_score`, excluding tier `refuted` and suppressed findings; thresholds MUST be >= 50 `critical`, >= 25 `poor`, >= 10 `moderate`, > 0 `good`, 0 `excellent`. When no scanner completed, posture MUST be `unknown`. Tiers `unverified`, `replay_verified` and `exploit_validated` contribute by their score.

#### Scenario: Risk by tier
- **GIVEN** one correlated `high` finding with tier `<tier>` and `confidence_score` `<score>`
- **WHEN** risk is assessed
- **THEN** the posture is `<posture>`

#### Examples:
| tier | score | posture |
|------|-------|---------|
| unverified | 0.5 | good |
| replay_verified | 0.9 | good |
| exploit_validated | 1.0 | moderate |
| refuted | 0.0 | excellent |

#### Scenario: All scanners failed
- **GIVEN** a scan where every scanner raised an error
- **WHEN** risk is assessed
- **THEN** the posture is `unknown`
- **AND** the scan state is `failed`

### Requirement: Findings are never silently dropped
The pipeline SHALL keep every correlated finding in the JSON report regardless of tier. Findings with tier `refuted` or a `suppression` MUST appear in the JSON and SARIF output and in a report appendix, and MUST be excluded from default report sections, risk and `--fail-on`. Findings with tier `unverified`, `replay_verified` or `exploit_validated` and no suppression MUST appear in default sections.

#### Scenario: Visibility by tier
- **GIVEN** a correlated finding with tier `<tier>` and suppression `<suppressed>`
- **WHEN** the JSON and Markdown reports are generated
- **THEN** the JSON report contains the finding
- **AND** the finding appears in the `<section>` section of the Markdown report

#### Examples:
| tier | suppressed | section |
|------|------------|---------|
| unverified | no | findings |
| replay_verified | no | findings |
| exploit_validated | no | findings |
| refuted | no | appendix |
| replay_verified | yes | appendix |

### Requirement: Ignore file
The CLI SHALL read `.haris-ignore.yaml` (or `--ignore-file <path>`) with `version: 1` and entries holding exactly one of `fingerprint` or `rule` (a `vuln_class` id, optionally with a `url` glob on the normalised URL) plus required `reason`, `expires` (ISO date) and `author`. A matching unexpired entry MUST set `suppression` on the finding for any tier (`unverified`, `replay_verified`, `exploit_validated`, `refuted`) and keep the finding. An expired entry MUST suppress nothing and emit a warning. An invalid file MUST exit with code 3.

#### Scenario: Ignore entry evaluation
- **GIVEN** today is 2026-11-08
- **AND** an ignore entry `<entry>`
- **WHEN** a finding of class `missing_header` at `https://example.com/static/app.js` is evaluated
- **THEN** the finding's suppression is `<result>`

#### Examples:
| entry | result |
|-------|--------|
| rule missing_header, url https://example.com/static/**, expires 2027-01-31 | set |
| rule missing_header, url https://example.com/api/**, expires 2027-01-31 | (absent) |
| rule missing_header, (no url), expires 2027-01-31 | set |
| rule missing_header, url https://example.com/static/**, expires 2026-11-01 | (absent) |
| rule insecure_cookie, (no url), expires 2027-01-31 | (absent) |

#### Scenario: Entry without reason
- **WHEN** the ignore file contains an entry with no `reason`
- **THEN** the CLI exits with code 3 before any request is sent

### Requirement: Scan diff
`haris diff <old.json> <new.json>` and `haris scan --baseline <old.json>` SHALL classify each `finding_id` as `new` (only in new), `fixed` (only in old and the old finding's scanner completed in the new scan), `not_retested` (only in old and that scanner did not complete) or `unchanged` (in both). The classification MUST apply to findings of every tier, and the output MUST report the tier of each side.

#### Scenario: Diff classes
- **GIVEN** an old report with finding `A` from `nuclei` and finding `B` from `wapiti`
- **AND** a new report with findings `A` and `C`, where `nuclei` completed and `wapiti` `<wapiti_state>`
- **WHEN** `haris diff` runs
- **THEN** `A` is `unchanged`, `C` is `new` and `B` is `<b_class>`

#### Examples:
| wapiti_state | b_class |
|--------------|---------|
| completed | fixed |
| timed out | not_retested |

### Requirement: Exit codes
The CLI SHALL exit `3` on usage or configuration errors, else `2` when the scan state is `incomplete`, `failed` or `cancelled`, else `1` when at least one correlated finding that is not `refuted` and not suppressed has severity at or above `--fail-on`, else `0`. Without `--fail-on`, exit code 1 MUST NOT occur. Tiers `unverified`, `replay_verified` and `exploit_validated` count toward `--fail-on`; `refuted` does not.

#### Scenario: Exit code matrix
- **GIVEN** a scan with state `<state>` and one `high` finding with tier `<tier>`
- **WHEN** the CLI runs with `<flag>`
- **THEN** the exit code is `<code>`

#### Examples:
| state | tier | flag | code |
|-------|------|------|------|
| completed | unverified | --fail-on high | 1 |
| completed | replay_verified | --fail-on critical | 0 |
| completed | exploit_validated | --fail-on medium | 1 |
| completed | refuted | --fail-on high | 0 |
| completed | unverified | (absent) | 0 |
| incomplete | unverified | --fail-on high | 2 |
| failed | unverified | (absent) | 2 |
| completed | unverified | --fail-on banana | 3 |
