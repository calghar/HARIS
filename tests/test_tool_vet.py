from haris.core.engine import ScanEngine
from haris.core.scanner import BaseScanner
from haris.models import Finding, ScannerResult, Target
from haris.models.scan_context import ScanContext
from haris.net.policy import NetworkPolicy
from haris.net.ssrf import Resolver
from haris.scanners.base import ExternalToolScanner


class _Probe(ExternalToolScanner):
    name = "nuclei"

    def __init__(self) -> None:
        super().__init__()
        self.started = False

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        self.started = True
        return ScannerResult(scanner_name=self.name)

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []


def _engine(
    scanner: BaseScanner, resolver: Resolver, *, allow_private: bool
) -> ScanEngine:
    return ScanEngine(
        scanners=[scanner],
        resolver=resolver,
        network_policy=NetworkPolicy(allow_private=allow_private),
    )


def test_h2_rebind_to_blocked_address_fails_the_scanner() -> None:
    calls = 0

    def resolver(_host: str, _port: int) -> list[str]:
        nonlocal calls
        calls += 1
        return ["93.184.216.34"] if calls == 1 else ["10.0.0.5"]

    probe = _Probe()
    session = _engine(probe, resolver, allow_private=False).run(
        Target(base_url="https://example.com")
    )
    text = " ".join(session.errors)
    assert calls >= 2
    assert probe.started is False
    assert "blocked address" in text
    assert "pre-flight" not in text


def test_h2_allow_private_loopback_still_starts_the_tool() -> None:
    calls = 0

    def resolver(_host: str, _port: int) -> list[str]:
        nonlocal calls
        calls += 1
        return ["127.0.0.1"]

    probe = _Probe()
    _engine(probe, resolver, allow_private=True).run(
        Target(base_url="http://localhost")
    )
    assert calls >= 2
    assert probe.started is True
