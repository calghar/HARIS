import abc
from pathlib import Path

from ..models import ScanSession


class BaseReporter(abc.ABC):
    """Abstract base class for all report generators."""

    format_name: str = "base"
    file_extension: str = ".txt"

    @abc.abstractmethod
    def generate(self, session: ScanSession) -> str:
        """Generate the report content as a string."""

    def write(self, session: ScanSession, output_path: str | Path) -> Path:
        """Generate and write the report to a file."""
        content = self.generate(session)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
