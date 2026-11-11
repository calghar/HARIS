# Delta for Finding identity

## ADDED Requirements

### Requirement: OWASP category from the canonical class
Every finding whose canonical class has an entry in the OWASP mapping SHALL carry that entry's category, regardless of scanner tags. Every class id in `vuln_classes.yaml` MUST either have a mapping entry or be listed in an explicit `unmapped` list in the same file. The class `cleartext_password_submission` MUST map to `A04:2025 - Cryptographic Failures` with CWE-319.

#### Scenario: Class mapping without a tag
- **GIVEN** a Wapiti finding of class `cleartext_password_submission` that carries no OWASP tag
- **WHEN** the scan finishes
- **THEN** its OWASP category is `A04:2025 - Cryptographic Failures`
- **AND** its CWE is `CWE-319`

#### Scenario: Mapping coverage
- **GIVEN** the class ids in `vuln_classes.yaml`
- **WHEN** each is looked up in the OWASP mapping and in the `unmapped` list
- **THEN** every class id is found in exactly one of them
