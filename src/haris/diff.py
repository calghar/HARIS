import enum
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models import Finding, ScanSession

NO_TIER = "-"
_ERROR_SCANNER = re.compile(r"^\[([^\]]+)\]")


class ReportError(ValueError):
    """A report file cannot be read (CLI exit code 3)."""


class DiffStatus(enum.StrEnum):
    NEW = "new"
    FIXED = "fixed"
    NOT_RETESTED = "not_retested"
    UNCHANGED = "unchanged"


class ReportFinding(BaseModel):
    finding: Finding
    scanners: list[str] = Field(default_factory=list)


class LoadedReport(BaseModel):
    """What a diff needs from a JSON report (0.6 and 0.7 layouts)."""

    findings: dict[str, ReportFinding] = Field(default_factory=dict)
    completed: set[str] = Field(default_factory=set)


class DiffEntry(BaseModel):
    finding_id: str
    status: DiffStatus
    title: str
    severity: str
    scanners: list[str]
    old_tier: str = NO_TIER
    new_tier: str = NO_TIER


def load_report(path: Path) -> LoadedReport:
    """Read a JSON report; raise ReportError when it is unreadable."""
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return _parse(data)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ReportError(f"cannot read report {path}: {exc}") from exc


def _parse(data: dict[str, Any]) -> LoadedReport:
    report = LoadedReport(completed=_completed_scanners(data))
    if "correlated" in data:
        for item in data["correlated"]:
            sources = item.get("sources", [])
            finding = Finding.from_dict(
                {k: v for k, v in item.items() if k != "sources"}
            )
            scanners = sorted({s[0] for s in sources}) or [finding.scanner]
            report.findings[finding.finding_id] = ReportFinding(
                finding=finding, scanners=scanners
            )
        return report
    for item in data["findings"]:
        finding = Finding.from_dict(item)
        known = report.findings.setdefault(
            finding.finding_id, ReportFinding(finding=finding)
        )
        if finding.scanner not in known.scanners:
            known.scanners.append(finding.scanner)
    return report


def _completed_scanners(data: dict[str, Any]) -> set[str]:
    meta = data.get("meta", {})
    if "scanner_status" in data:
        return {
            n for n, state in data["scanner_status"].items() if state == "completed"
        }
    failed = {
        m.group(1)
        for error in data.get("errors", [])
        if (m := _ERROR_SCANNER.match(error))
    }
    return set(meta.get("scanners_used", [])) - failed


def diff_reports(old: LoadedReport, new: LoadedReport) -> list[DiffEntry]:
    """Classify each finding id as new, fixed, not_retested or unchanged."""
    entries = []
    for fid, item in new.findings.items():
        before = old.findings.get(fid)
        status = DiffStatus.UNCHANGED if before else DiffStatus.NEW
        entries.append(_entry(fid, status, item, before, item))
    for fid, item in old.findings.items():
        if fid in new.findings:
            continue
        retested = bool(item.scanners) and all(
            s in new.completed for s in item.scanners
        )
        status = DiffStatus.FIXED if retested else DiffStatus.NOT_RETESTED
        entries.append(_entry(fid, status, item, item, None))
    return entries


def _entry(
    finding_id: str,
    status: DiffStatus,
    shown: ReportFinding,
    old: ReportFinding | None,
    new: ReportFinding | None,
) -> DiffEntry:
    return DiffEntry(
        finding_id=finding_id,
        status=status,
        title=shown.finding.title,
        severity=shown.finding.severity.value,
        scanners=shown.scanners,
        old_tier=old.finding.verification.tier.value if old else NO_TIER,
        new_tier=new.finding.verification.tier.value if new else NO_TIER,
    )


def format_diff(entries: list[DiffEntry]) -> str:
    """One line per finding (tier shown as ``old -> new``) and a summary line."""
    lines = [
        f"{e.status.value:<13} {e.severity:<8} {e.old_tier} -> {e.new_tier}  "
        f"{e.finding_id}  {e.title}"
        for e in sorted(
            entries, key=lambda e: (list(DiffStatus).index(e.status), e.severity)
        )
    ]
    counts = {s: sum(1 for e in entries if e.status == s) for s in DiffStatus}
    lines.append(", ".join(f"{n} {s.value}" for s, n in counts.items()))
    return "\n".join(lines)


def report_from_session(session: ScanSession) -> LoadedReport:
    """The diff view of a finished scan, without a JSON round trip."""
    return LoadedReport(
        findings={
            c.canonical.finding_id: ReportFinding(
                finding=c.canonical, scanners=sorted({s for s, _ in c.sources})
            )
            for c in session.correlated
        },
        completed={n for n, s in session.scanner_status.items() if s == "completed"},
    )
