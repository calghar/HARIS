import logging
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from ..diff import LoadedReport
from ..models import ScanSession
from .base import BaseReporter
from .csv_report import CSVReporter
from .html_report import HTMLReporter
from .json_report import JSONReporter
from .junit_report import JUnitReporter
from .markdown_report import MarkdownReporter
from .sarif_report import SARIFReporter

REPORTER_REGISTRY: dict[str, type[BaseReporter]] = {
    "json": JSONReporter,
    "markdown": MarkdownReporter,
    "html": HTMLReporter,
    "sarif": SARIFReporter,
    "csv": CSVReporter,
    "junit": JUnitReporter,
}


def domain_slug(url: str) -> str:
    """Filesystem-safe hostname for report file names."""
    hostname = urlparse(url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)


def write_reports(
    session: ScanSession,
    output_dir: Path,
    formats: Iterable[str],
    baseline: LoadedReport | None = None,
) -> list[Path]:
    """Write one report per format. Unknown formats are skipped."""
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = domain_slug(session.target.base_url)
    written: list[Path] = []
    for fmt in formats:
        reporter_cls = REPORTER_REGISTRY.get(fmt)
        if reporter_cls is None:
            logging.warning("Unknown report format: %s", fmt)
            continue
        reporter = reporter_cls(baseline=baseline)
        filename = f"report_{domain}_{session.session_id}{reporter.file_extension}"
        written.append(reporter.write(session, output_dir / filename))
    return written


__all__ = [
    "BaseReporter",
    "CSVReporter",
    "HTMLReporter",
    "JSONReporter",
    "JUnitReporter",
    "MarkdownReporter",
    "SARIFReporter",
    "REPORTER_REGISTRY",
    "domain_slug",
    "write_reports",
]
