import json
import os
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from haris.core.engine import ScanEngine
from haris.core.exit_codes import exit_code
from haris.data.scanner_config import get_nuclei_phase2_timeout
from haris.models import ScanState
from haris.models.target import Scope, Target
from haris.reporting.json_report import JSONReporter
from haris.reporting.markdown_report import MarkdownReporter
from haris.scanners.nuclei_scanner import NucleiScanner
from haris.scanners.option_policy import prepare_web_scanner_options
from tests.conftest import bound_context
from tests.test_engine_pipeline import TARGET

FINDINGS = (
    Path(__file__).parent / "fixtures" / "scanners" / "nuclei" / "phase2_scan.jsonl"
)
BOUND_S = 3
BOUND_NOTE = (
    f"phase 2 stopped at the {BOUND_S} s limit (scanners.nuclei.phase2_timeout_s)"
)


class Stub:
    def __init__(self, calls: Path, pids: Path) -> None:
        self.calls = calls
        self.pids = pids

    def runs(self) -> list[str]:
        return self.calls.read_text().splitlines()

    def child_pid(self) -> int:
        return int(self.pids.read_text())


type Install = Callable[[bool], Stub]


@pytest.fixture
def target() -> Target:
    return Target(base_url="http://127.0.0.1:18080", scope=Scope())


@pytest.fixture
def install_stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Install:
    """Put a stub ``nuclei`` on PATH: one finding, then optionally hang with a child."""

    def install(hang: bool) -> Stub:
        stub = Stub(tmp_path / "calls.log", tmp_path / "child.pid")
        hang_lines = f"sleep 60 &\necho $! > {stub.pids}\nsleep 60\n" if hang else ""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / "nuclei"
        script.write_text(
            "#!/bin/sh\n"
            f'echo "$@" >> {stub.calls}\n'
            'case " $* " in *" -et "*) exit 0;; esac\n'
            f"head -n 1 {FINDINGS}\n"
            f"{hang_lines}"
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        # A new file's first exec can stall for seconds on macOS; keep it off the bound.
        subprocess.run([script, "-et"], check=True)
        stub.calls.unlink()
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setattr(
            NucleiScanner, "_check_templates_available", lambda _s: True
        )
        monkeypatch.setattr(NucleiScanner, "_template_root", lambda _s: None)
        return stub

    return install


def pid_gone(pid: int, wait_s: float = 3.0) -> bool:
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def scanner(**options: Any) -> NucleiScanner:
    return NucleiScanner({"skip_tech_detection": True, **options})


class TestOverTheBound:
    def test_group_killed_findings_kept_status_partial(
        self, install_stub: Install, target: Target
    ) -> None:
        stub = install_stub(True)
        result = scanner(phase2_timeout_s=BOUND_S).scan(target, bound_context())

        assert pid_gone(stub.child_pid()), "child of nuclei outlived the bound"
        assert len(result.findings) == 1
        assert result.errors == []
        assert result.status == "partial"
        assert BOUND_NOTE in (result.note or "")

    def test_scan_stays_completed_and_reports_list_the_note(
        self, install_stub: Install
    ) -> None:
        install_stub(True)
        session = ScanEngine(
            scanners=[scanner(phase2_timeout_s=BOUND_S)], parallel=1
        ).run(TARGET)

        assert session.scan_state is ScanState.COMPLETED
        assert session.scanner_status == {"nuclei": "partial"}
        assert exit_code(session, None) == 0
        data = json.loads(JSONReporter().generate(session))
        assert BOUND_NOTE in data["scanner_notes"]["nuclei"]
        assert BOUND_NOTE.split(" (")[0] in MarkdownReporter().generate(session)

    def test_broad_run_using_the_budget_skips_the_targeted_run(
        self, install_stub: Install, target: Target
    ) -> None:
        stub = install_stub(True)
        result = scanner(phase2_timeout_s=BOUND_S, automatic_scan=True).scan(
            target, bound_context()
        )

        assert result.status == "partial"
        assert len(stub.runs()) == 1, stub.runs()
        assert "-et" not in stub.runs()[0].split()


class TestWithinTheBound:
    def test_status_completed_and_targeted_run_happens(
        self, install_stub: Install, target: Target
    ) -> None:
        stub = install_stub(False)
        result = scanner(phase2_timeout_s=30, automatic_scan=True).scan(
            target, bound_context()
        )

        assert result.status == "completed"
        assert not result.note
        assert "status" not in result.metadata
        assert len(stub.runs()) == 2

    def test_per_run_timeout_below_the_bound_is_still_an_error(
        self, install_stub: Install, target: Target
    ) -> None:
        install_stub(True)
        result = scanner(phase2_timeout_s=30, timeout=1).scan(target, bound_context())

        assert result.status == "failed"
        assert "timed out after 1s" in result.errors[0]
        assert len(result.findings) == 1


class TestLimitSource:
    def test_yaml_default_is_300(self) -> None:
        assert get_nuclei_phase2_timeout() == 300
        assert NucleiScanner()._phase2_limit() == 300

    def test_option_overrides_yaml(self) -> None:
        assert NucleiScanner({"phase2_timeout_s": 7})._phase2_limit() == 7

    def test_web_option_policy_accepts_the_option(self) -> None:
        options = {"nuclei": {"phase2_timeout_s": 60}}
        assert prepare_web_scanner_options(options) == options
        with pytest.raises(ValueError, match="not a valid value"):
            prepare_web_scanner_options({"nuclei": {"phase2_timeout_s": "soon"}})
