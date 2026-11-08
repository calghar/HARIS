import abc

from ..core.scanner import BaseScanner
from ..models import Finding, ScanContext, ScannerResult, Target
from ..net import NetworkError, ScopedClient
from .requesting import scan_client


class ProbeScanner(BaseScanner):
    """A check that probes the target over the scan's ``ScopedClient``."""

    @abc.abstractmethod
    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        """Send the check's requests and return its findings."""

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        with scan_client(target, context) as client:
            try:
                result.findings = self.probe(client, target)
            except NetworkError as exc:
                result.errors.append(f"{type(exc).__name__}: {exc}")
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []
