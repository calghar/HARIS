## MODIFIED Requirements
<!-- Copy the ENTIRE requirement block from openspec/specs/<capability>/spec.md, then edit. Header must match. -->

### Requirement: <!-- exact existing name -->
<!-- full updated SHALL/MUST text -->

#### Scenario: <!-- preserved-behavior scenario — guards against regression -->
- **GIVEN** <!-- precondition; omit when the trigger needs no setup -->
- **WHEN** <!-- condition -->
- **THEN** <!-- expected outcome (unchanged behavior stated so a test can guard it) -->

## ADDED Requirements

### Requirement: <!-- new requirement name -->
<!-- SHALL/MUST text -->

#### Scenario: <!-- scenario name -->
- **GIVEN** <!-- precondition; omit when the trigger needs no setup -->
- **WHEN** <!-- condition -->
- **THEN** <!-- expected outcome -->
<!-- - **AND** / - **BUT** continue the preceding keyword -->

<!-- Failure matrix — steps carry <placeholder>s named by the table header.
     Generates a Scenario Outline: one test per row. No blank cells — write (absent).

#### Scenario: <!-- scenario name -->
- **WHEN** <!-- trigger involving <input> -->
- **THEN** <!-- the outcome is <result> -->

#### Examples:
| input | result |
|-------|--------|
-->

## REMOVED Requirements
<!-- Only if removing. Each needs Reason + Migration. Delete this section if unused. -->

### Requirement: <!-- name -->
**Reason**: <!-- why removed -->
**Migration**: <!-- what callers do instead -->
