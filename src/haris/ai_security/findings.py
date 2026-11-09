from collections.abc import Iterable

from ..models import (
    EvidenceExchange,
    Finding,
    Severity,
    Verification,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from .owasp_ai import load_mappings, risk_label

SCANNER_NAME = "ai_security"
CLASS_PREFIX = "ai_"
AI_TAG = "ai"


def ai_finding(
    kind: str,
    *,
    url: str,
    label: str = "",
    detail: str = "",
    evidence: str = "",
    parameter: str = "",
    method: str = "GET",
    severity: Severity | None = None,
    exchanges: Iterable[EvidenceExchange] = (),
    digest: str = "",
) -> Finding:
    """A finding for mapping *kind*; *digest* tells repeats apart for replay."""
    mappings = load_mappings()
    mapping = mappings.checks[kind]
    finding = Finding(
        title=mapping.title.format(label=label),
        description=" ".join(
            part for part in (mapping.description.format(label=label), detail) if part
        ),
        severity=severity or mapping.severity,
        confidence_score=mapping.confidence,
        owasp_category=risk_label(mapping.owasp[0]) if mapping.owasp else "",
        cwe_id=mapping.cwe,
        url=url,
        method=method,
        parameter=parameter,
        evidence=evidence,
        remediation=mapping.remediation,
        references=mappings.reference_urls(mapping.owasp),
        scanner=SCANNER_NAME,
        vuln_class=CLASS_PREFIX + kind,
        tags=[AI_TAG, *mapping.owasp],
        raw_data={"kind": kind, "digest": digest},
    )
    finding.verification.evidence = list(exchanges)
    return finding


def _key(finding: Finding) -> tuple[str, str, str, str]:
    return (
        finding.vuln_class,
        finding.url,
        finding.parameter,
        str(finding.raw_data.get("digest", "")),
    )


def confirm_by_replay(first: list[Finding], second: list[Finding]) -> list[Finding]:
    """Mark each first-run finding replay-verified when the second run found it too."""
    seen = {_key(f) for f in second}
    for finding in first:
        kind = str(finding.raw_data["kind"])
        verification: Verification = finding.verification
        verification.method = VerificationMethod.REPLAY
        verification.oracle = VerificationOracle(load_mappings().checks[kind].oracle)
        verification.advance(
            VerificationTier.REPLAY_VERIFIED
            if _key(finding) in seen
            else VerificationTier.REFUTED
        )
    return first
