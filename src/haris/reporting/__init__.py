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

__all__ = [
    "BaseReporter",
    "CSVReporter",
    "HTMLReporter",
    "JSONReporter",
    "JUnitReporter",
    "MarkdownReporter",
    "SARIFReporter",
    "REPORTER_REGISTRY",
]
