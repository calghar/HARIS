from pathlib import Path

from .diff import LoadedReport, diff_reports, format_diff, report_from_session
from .ignore import DEFAULT_IGNORE_FILE, IgnoreFile, load_ignore_file
from .models import ScanSession

PARTIAL_SESSION_FILE = "session.partial.json"


def resolve_ignore_file(path: str | None) -> IgnoreFile | None:
    """The explicit file (must exist) or ``./.haris-ignore.yaml`` when present."""
    if path:
        return load_ignore_file(Path(path))
    default = Path(DEFAULT_IGNORE_FILE)
    return load_ignore_file(default) if default.is_file() else None


def write_partial_session(session: ScanSession, output_dir: Path) -> Path:
    """Dump the session so far (credentials excluded) after each scanner."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / PARTIAL_SESSION_FILE
    path.write_text(
        session.model_dump_json(exclude={"target": {"auth"}}, indent=2),
        encoding="utf-8",
    )
    return path


def baseline_summary(session: ScanSession, baseline: LoadedReport) -> str:
    return format_diff(diff_reports(baseline, report_from_session(session)))
