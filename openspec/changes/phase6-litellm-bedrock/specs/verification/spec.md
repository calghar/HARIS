# Delta for Verification

## ADDED Requirements

### Requirement: Calibrated LLM abstain threshold
The shipped default of `verify.llm.abstain_below` SHALL be the lowest value on the grid 0.50, 0.55, ..., 0.95 at which the `confirmed` verdicts of the labelled bench set that are not abstained, run through the `litellm` backend, reach precision of at least 0.95 against the labels. WHEN no threshold reaches 0.95, the default MUST stay 0.7 and `docs/verification.md` MUST state that it is uncalibrated. The raw per-case verdicts, confidences, labels and the model string MUST be committed under `bench/results/` and cited in `docs/verification.md`.

#### Scenario: Threshold selection
- **GIVEN** labelled verdicts where `confirmed` precision is `<p_low>` at 0.5, `<p_mid>` at 0.7 and `<p_high>` at 0.9, and the grid points between them lie on the lower of their neighbours
- **WHEN** the default is chosen
- **THEN** `abstain_below` is `<default>`

#### Examples:
| p_low | p_mid | p_high | default |
|-------|-------|--------|---------|
| 0.97 | 0.98 | 1.00 | 0.5 |
| 0.90 | 0.96 | 1.00 | 0.7 |
| 0.80 | 0.90 | 0.96 | 0.9 |
| 0.80 | 0.85 | 0.90 | 0.7, documented as uncalibrated |

### Requirement: Replay coverage for Wapiti classes
The replay verifier SHALL give each of the classes `sqli_error`, `xss_reflected`, `command_injection`, `path_traversal` and `open_redirect` a deterministic oracle that compares a probe with a control, with these positive conditions:

- `command_injection`: probe time exceeds control time by the `timing` rule of `verify.timing`, using only delay payloads (`sleep {d}` forms) that run no other command.
- `path_traversal`: the probe body matches `root:[x*]:0:0:` or `\[boot loader\]`, and the control body does not.
- `open_redirect`: the probe answers `3xx` with a `Location` whose host equals the probe's marker host (`haris-<16 hex>.invalid`), and the control does not.

Findings of class `ssrf` and `xxe` MUST stay `unverified` with method `none`; no out-of-band callback listener exists in this release. All oracle results follow the tier rules of "Deterministic replay verifier". On the bench run of DVWA with replay on, `verified_precision` MUST be at least 0.95 over at least 10 `replay_verified` findings.

#### Scenario: Oracle matrix for new classes
- **GIVEN** a finding of class `<class>`
- **WHEN** the probe and control responses are `<observation>`
- **THEN** its tier is `<tier>`

#### Examples:
| class | observation | tier |
|-------|-------------|------|
| path_traversal | probe body has `root:x:0:0:root:/root:/bin/bash`, control does not | replay_verified |
| path_traversal | probe and control both have `root:x:0:0:` | unverified |
| open_redirect | probe 302 `Location: http://haris-0123456789abcdef.invalid/`, control 200 | replay_verified |
| open_redirect | probe 302 to the login page, control 302 to the login page | unverified |
| command_injection | probe 5.3 s, control 0.2 s with D=5 | replay_verified |
| command_injection | probe 0.3 s, control 0.2 s with D=5 | unverified |
| ssrf | any | unverified, method none |
| xxe | any | unverified, method none |

#### Scenario: Precision target
- **GIVEN** the DVWA bench run with replay on
- **WHEN** the scorer reports tiers
- **THEN** at least 10 findings are `replay_verified`
- **AND** `verified_precision` is at least 0.95

### Requirement: Redirect catch-all hosts
WHEN a path probe returns `3xx` and its `Location`, with the random segment removed, equals that of a host control, the baseline SHALL NOT report the path, and an external finding of that path SHALL become `refuted` on replay. A `3xx` probe with a `Location` that differs from every control keeps the existing behavior.

#### Scenario: Redirect controls
- **GIVEN** every control to `/haris-<r>` answers `302` with `Location: /login`
- **WHEN** the probe of `<path>` answers `<probe>`
- **THEN** the outcome is `<outcome>`

#### Examples:
| path | probe | outcome |
|------|-------|---------|
| /.git/config | 302 `/login` | not reported; replayed finding refuted |
| /admin | 302 `/login` | not reported; replayed finding refuted |
| /admin | 302 `/admin/index.html` | existing behavior |
| /.git/config | 404 | existing behavior |

### Requirement: Agent PoC re-execution covers every request
The re-execution of an agent PoC SHALL send every PoC request in order, each with its control, through `ScopedClient`, so the scan rate limit of scoped-http applies to each send. It SHALL stop after `verify.poc_max_requests` sends (default 20, controls included), and every send counts toward `Scope.max_requests`. The finding MUST reach `exploit_validated` when at least one sent request is oracle-positive, and MUST otherwise keep its prior tier.

#### Scenario: Several PoC requests
- **GIVEN** an agent PoC with three requests whose oracle results are `<results>`
- **WHEN** the PoC is re-executed with budget for all three
- **THEN** the finding's tier is `<tier>`

#### Examples:
| results | tier |
|---------|------|
| positive, positive, positive | exploit_validated |
| positive, inconclusive, inconclusive | exploit_validated |
| inconclusive, positive, inconclusive | exploit_validated |
| inconclusive, inconclusive, inconclusive | prior tier kept |

#### Scenario: PoC request cap
- **GIVEN** `verify.poc_max_requests` is 20 and a PoC of 15 requests
- **WHEN** the PoC is re-executed
- **THEN** exactly 20 requests are sent, the first 10 PoC requests each followed by its control, in order

#### Scenario: PoC rate limit
- **GIVEN** the scope rate limit is `<rps>` requests per second and a PoC of 10 requests
- **WHEN** the PoC is re-executed
- **THEN** the 20 sends are spaced by the client rate limit of `<rps>` requests per second

#### Examples:
| rps |
|-----|
| 5 |
| 20 |

### Requirement: Replay control timeout and failed-scan notes
Soft-404 control requests of replay MUST use `verify.request_timeout_s`. WHEN a scan ends in state `failed`, the notes recorded for skipped stages MUST remain in the stored session `errors`.

#### Scenario: Control timeout
- **GIVEN** `verify.request_timeout_s` is 10 and the scan `NetworkPolicy.timeout_s` is 30
- **WHEN** the replay verifier sends a soft-404 control request that never answers
- **THEN** the request is abandoned after 10 seconds

#### Scenario: Failed scan keeps its notes
- **GIVEN** the replay stage was skipped with the note `<note>` and the scan then ended `failed`
- **WHEN** the session is stored and read back
- **THEN** `errors` contains `<note>`

### Requirement: Classified external noise
A nikto finding whose message starts with `This might be interesting` SHALL carry class `unclassified:nikto:interesting_path` and severity `info`, SHALL be replayed with the `soft404` oracle under the unclassified-external rule, and MUST NOT be hidden. On the bench run of Juice Shop, WebGoat and the `spa_catchall` fixture, the nuclei template `gocd-encryption-key` on the `security.txt` prefix route and the WebGoat `trace.axd` header finding MUST each be absent or `refuted`.

#### Scenario: Nikto interesting path
- **GIVEN** a nikto item `/ftp/: This might be interesting.`
- **WHEN** the scan finishes
- **THEN** the finding has class `unclassified:nikto:interesting_path`, severity `info` and appears in every report

#### Scenario: Named noise
- **GIVEN** the bench run of `<target>`
- **WHEN** the scorer lists findings
- **THEN** `<item>` is absent or has tier `refuted`

#### Examples:
| target | item |
|--------|------|
| juice-shop | nuclei `gocd-encryption-key` on the `security.txt` prefix route |
| webgoat | nikto `trace.axd` header finding |
