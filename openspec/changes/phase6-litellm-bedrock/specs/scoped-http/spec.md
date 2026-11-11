# Delta for Scoped HTTP

## ADDED Requirements

### Requirement: External tools connect only to vetted addresses
An external scanner (nuclei, nmap, nikto, sslyze, Wapiti) SHALL connect only to addresses that passed the SSRF check of `ScopedClient` at its pre-flight. WHEN a tool can neither be bound to those addresses nor run in a network that blocks private, loopback and link-local ranges, it MUST NOT start and the scan MUST record an error for it. This applies to every re-resolution of the target host during the tool's run, including DNS answers that change after the pre-flight.

#### Scenario: Rebinding after pre-flight
- **GIVEN** the target host resolves to `93.184.216.34` at pre-flight and to `127.0.0.1` for every later lookup
- **WHEN** `<tool>` runs
- **THEN** the tool opens no connection to `127.0.0.1`

#### Examples:
| tool |
|------|
| nuclei |
| nmap |
| nikto |
| sslyze |
| wapiti |

#### Scenario: Tool that cannot be bound
- **GIVEN** a tool with no address binding and no blocking network available
- **WHEN** the scan starts
- **THEN** the tool is not executed
- **AND** `errors` holds one entry naming the tool and the reason

### Requirement: Bounded nuclei phase 2
Nuclei phase 2 SHALL be limited by `scanners.nuclei.phase2_timeout_s` (default 300). WHEN the limit is reached the process MUST be killed, the findings read so far MUST be kept, and the scanner status MUST be `partial` with a note in the scanner result stating the limit. A `partial` scanner MUST NOT make the scan state `incomplete` or change the exit code, and every report MUST list the note.

#### Scenario: Phase 2 over the bound
- **GIVEN** `phase2_timeout_s` is 300 and phase 2 would run 531 s
- **WHEN** the scan runs
- **THEN** the nuclei process is killed at 300 s
- **AND** scanner status of `nuclei` is `partial`, scan state is `completed` and the exit code is not `2` because of it
- **AND** the JSON and Markdown reports list the note

#### Scenario: Phase 2 within the bound
- **GIVEN** `phase2_timeout_s` is 300 and phase 2 ends after 120 s
- **WHEN** the scan runs
- **THEN** scanner status of `nuclei` is `completed`

### Requirement: Scanners not applicable are skipped
WHEN the target URL scheme is `http` and the scan discovered no TLS port, the `sslyze` scanner SHALL NOT run and its status MUST be `skipped` with the note `no TLS endpoint`. A `skipped` scanner MUST NOT count against completion: the scan state is computed from the other scanners. WHEN the target scheme is `https`, or a TLS port was discovered, `sslyze` MUST run as before.

#### Scenario: sslyze on plain HTTP
- **GIVEN** target `http://host:8080` with no TLS port discovered and scanners `nmap` and `sslyze`
- **WHEN** both finish and nmap completed
- **THEN** `sslyze` has status `skipped` and note `no TLS endpoint`
- **AND** the scan state is `completed`

#### Scenario: Every scanner skipped
- **GIVEN** target `http://host:8080` with no TLS port discovered and scanners `sslyze` only
- **WHEN** the scan finishes
- **THEN** the scan state is `completed`
- **AND** the report lists the `no TLS endpoint` note

#### Scenario: sslyze on HTTPS
- **GIVEN** target `https://host` and scanner `sslyze`
- **WHEN** the scan runs
- **THEN** `sslyze` is executed
