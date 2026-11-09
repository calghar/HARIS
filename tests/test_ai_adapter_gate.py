from pathlib import Path

import pytest

from haris.core.engine import ScanEngine
from haris.models import ScanState, Scope, Target
from haris.scanners import SCANNER_REGISTRY
from haris.scanners.garak_scanner import GarakScanner
from haris.scanners.promptfoo_scanner import PromptfooScanner

from .adapter_support import BOTH, run
from .test_engine_pipeline import Probe, finding


class TestMissingBinary:
    @pytest.fixture(autouse=True)
    def empty_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PATH", str(tmp_path))

    @pytest.mark.parametrize("cls", [GarakScanner, PromptfooScanner])
    def test_error_recorded(self, cls) -> None:
        result = run(cls, **BOTH)
        assert result.errors and cls.name in result.errors[0]
        assert result.findings == []

    def test_other_scanners_still_report_and_scan_is_incomplete(self) -> None:
        target = Target(
            base_url="https://example.com", scope=Scope(rate_limit_rps=10.0)
        )
        nuclei_finding = finding("Exposed", "https://example.com/a", "nuclei")
        session = ScanEngine(
            scanners=[
                GarakScanner(dict(BOTH)),
                Probe("nuclei", findings=[nuclei_finding]),
            ],
            parallel=1,
        ).run(target)
        assert session.scanner_status == {"garak": "failed", "nuclei": "completed"}
        assert session.scan_state is ScanState.INCOMPLETE
        assert len(session.all_findings) == 1
        assert any("garak" in e for e in session.errors)


def test_adapters_are_registered() -> None:
    assert SCANNER_REGISTRY["garak"] is GarakScanner
    assert SCANNER_REGISTRY["promptfoo"] is PromptfooScanner
