"""Report generators for scan results."""

from .base import BaseReporter
from .html_report import HTMLReporter
from .json_report import JSONReporter
from .markdown_report import MarkdownReporter

REPORTER_REGISTRY: dict[str, type[BaseReporter]] = {
    "json": JSONReporter,
    "markdown": MarkdownReporter,
    "html": HTMLReporter,
}

__all__ = [
    "BaseReporter",
    "JSONReporter",
    "MarkdownReporter",
    "HTMLReporter",
    "REPORTER_REGISTRY",
]
