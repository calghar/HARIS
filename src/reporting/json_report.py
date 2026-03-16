import json

from ..models import ScanSession
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """Generates a structured JSON report.

    Suitable for integration with dashboards, CI pipelines, or other
    automated tooling.
    """

    format_name = "json"
    file_extension = ".json"

    def generate(self, session: ScanSession) -> str:
        report = {
            "meta": {
                "session_id": session.session_id,
                "target": session.target.base_url,
                "profile": session.profile_name or "",
                "started_at": session.started_at,
                "finished_at": session.finished_at,
                "duration_seconds": session.duration_seconds,
                "scanners_used": session.scanners_used,
            },
            "risk_posture": {
                "level": session.risk_posture.value,
                "description": session.risk_posture_text,
            },
            "summary": session.summary(),
            "findings": [f.to_dict() for f in session.all_findings],
            "remediation": [
                {
                    "title": s.title,
                    "description": s.description,
                    "effort": s.effort.value,
                    "impact": s.impact.value,
                    "finding_count": s.finding_count,
                    "category": s.category,
                }
                for s in session.remediation_steps
            ],
            "errors": session.errors,
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
