from ..models import CorrelatedFinding, Finding
from .confidence import consensus, prior_for, rescore
from .identity import FINDING_ID_LENGTH, identify


def pick_best(bucket: list[Finding]) -> Finding:
    """Highest tier, then severity, then confidence."""
    return max(
        bucket,
        key=lambda f: (f.verification.tier.rank, -f.severity.sort_key, prior_for(f)),
    )


class FindingCorrelator:
    """Group findings by fingerprint into one correlated finding per issue.

    Inputs are never modified; the canonical finding is a deep copy.
    """

    def correlate(
        self, findings: list[Finding], base_url: str = ""
    ) -> list[CorrelatedFinding]:
        buckets: dict[str, list[Finding]] = {}
        classes: dict[str, str] = {}
        for finding in findings:
            class_id, fingerprint = identify(finding, base_url)
            buckets.setdefault(fingerprint, []).append(finding)
            classes[fingerprint] = class_id

        correlated = [
            self._merge(fingerprint, classes[fingerprint], bucket)
            for fingerprint, bucket in buckets.items()
        ]
        correlated.sort(
            key=lambda c: (
                not c.multi_confirmed,
                c.canonical.severity.sort_key,
                -c.canonical.confidence_score,
            )
        )
        return correlated

    @staticmethod
    def _merge(
        fingerprint: str, class_id: str, bucket: list[Finding]
    ) -> CorrelatedFinding:
        best = pick_best(bucket)
        canonical = best.model_copy(deep=True)
        canonical.vuln_class = class_id
        canonical.fingerprint = fingerprint
        canonical.finding_id = fingerprint[:FINDING_ID_LENGTH]
        canonical.severity = min(bucket, key=lambda f: f.severity.sort_key).severity

        per_scanner: dict[str, float] = {}
        for f in bucket:
            per_scanner[f.scanner] = max(per_scanner.get(f.scanner, 0.0), prior_for(f))

        merged = CorrelatedFinding(
            canonical=canonical,
            sources=[(f.scanner, f.observation_id) for f in bucket],
            consensus_score=consensus(per_scanner.values()),
        )
        rescore(merged)
        return merged
