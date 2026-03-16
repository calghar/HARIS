import hashlib
import logging
from urllib.parse import urlparse

from ..models import Confidence, CorrelatedFinding, Finding

logger = logging.getLogger(__name__)


class FindingCorrelator:
    """Correlate and de-duplicate findings from multiple scanners.

    The correlator uses a fingerprint based on the normalised URL path,
    HTTP parameter, vulnerability type (OWASP tag or title keyword),
    and HTTP method.  Findings with the same fingerprint are merged.

    When merging, the finding with the highest confidence wins as
    the canonical entry.  If confidence is equal, the one with the
    higher severity wins.  All contributing scanners are recorded
    in ``sources``.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, list[Finding]] = {}

    def correlate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        """Group, merge, and return correlated findings."""
        self._buckets.clear()

        for f in findings:
            key = self._fingerprint(f)
            self._buckets.setdefault(key, []).append(f)

        correlated: list[CorrelatedFinding] = []
        for _key, bucket in self._buckets.items():
            canonical = self._pick_canonical(bucket)
            sources = [(f.scanner, f.finding_id) for f in bucket]

            # Boost confidence when multiple scanners agree
            if len({s[0] for s in sources}) > 1:
                canonical.confidence = Confidence.CONFIRMED

            cf = CorrelatedFinding(canonical=canonical, sources=sources)
            correlated.append(cf)

        # Sort: multi-confirmed first, then by severity
        correlated.sort(
            key=lambda c: (
                not c.multi_confirmed,
                c.canonical.severity.sort_key,
            )
        )
        return correlated

    @staticmethod
    def _fingerprint(f: Finding) -> str:
        """Compute a stable fingerprint for correlation.

        Two findings match if they concern the same URL path, parameter,
        vulnerability type, and HTTP method.
        """
        parsed = urlparse(f.url)
        path = parsed.path.rstrip("/") or "/"

        # Normalise vuln type from tags or title
        vuln_type = ""
        if f.tags:
            vuln_type = f.tags[0]
        elif f.owasp_category:
            vuln_type = f.owasp_category
        else:
            # Fall back to first two title words lowercased
            vuln_type = "_".join(f.title.lower().split()[:3])

        raw = f"{parsed.hostname}|{path}|{f.parameter}|{vuln_type}|{f.method}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _pick_canonical(bucket: list[Finding]) -> Finding:
        """Choose the best representative from a group of duplicates."""
        confidence_rank = {
            Confidence.CONFIRMED: 0,
            Confidence.FIRM: 1,
            Confidence.TENTATIVE: 2,
        }
        bucket.sort(
            key=lambda f: (
                confidence_rank.get(f.confidence, 3),
                f.severity.sort_key,
            )
        )
        return bucket[0]
