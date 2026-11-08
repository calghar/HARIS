import csv
import io

from ..models import Finding, ScanSession
from .base import BaseReporter
from .escape import csv_cell
from .findings import report_findings

COLUMNS = (
    "finding_id",
    "fingerprint",
    "severity",
    "confidence",
    "confidence_score",
    "verification",
    "status",
    "vuln_class",
    "title",
    "cwe_id",
    "owasp_category",
    "method",
    "url",
    "parameter",
    "scanner",
    "description",
    "evidence",
    "remediation",
)


class CSVReporter(BaseReporter):
    """One row per finding; ``status`` is active, refuted or suppressed."""

    format_name = "csv"
    file_extension = ".csv"

    def generate(self, session: ScanSession) -> str:
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(COLUMNS)
        for f in report_findings(session):
            writer.writerow(csv_cell(v) for v in _row(f))
        return out.getvalue()


def _row(f: Finding) -> list[str]:
    status = (
        "suppressed"
        if f.suppression
        else "active"
        if f.is_active
        else f.verification.tier.value
    )
    values = {
        **f.to_dict(),
        "verification": f.verification.tier.value,
        "status": status,
    }
    return [str(values[c]) for c in COLUMNS]
