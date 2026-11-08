import json
from pathlib import Path

import pytest

from haris.cli import main
from haris.core.exit_codes import exit_code
from haris.core.runner import ScanRunner
from haris.models import (
    CorrelatedFinding,
    Finding,
    ScanSession,
    ScanState,
    Severity,
    Target,
    Verification,
    VerificationTier,
)
from tests.test_engine_pipeline import Probe, finding

T = VerificationTier
S = ScanState


def session_with(state: ScanState, tier: VerificationTier) -> ScanSession:
    high = Finding(
        title="x",
        description="",
        severity=Severity.HIGH,
        verification=Verification(tier=tier),
    )
    return ScanSession(
        session_id="s",
        target=Target(base_url="https://example.com"),
        scan_state=state,
        correlated=[CorrelatedFinding(canonical=high, sources=[("x", "o")])],
    )


@pytest.mark.parametrize(
    ("state", "tier", "fail_on", "code"),
    [
        (S.COMPLETED, T.UNVERIFIED, Severity.HIGH, 1),
        (S.COMPLETED, T.REPLAY_VERIFIED, Severity.CRITICAL, 0),
        (S.COMPLETED, T.EXPLOIT_VALIDATED, Severity.MEDIUM, 1),
        (S.COMPLETED, T.REFUTED, Severity.HIGH, 0),
        (S.COMPLETED, T.UNVERIFIED, None, 0),
        (S.INCOMPLETE, T.UNVERIFIED, Severity.HIGH, 2),
        (S.FAILED, T.UNVERIFIED, None, 2),
        (S.CANCELLED, T.UNVERIFIED, None, 2),
    ],
)
def test_exit_code_matrix(state, tier, fail_on, code):
    """Scenario: Exit code matrix (rows 1-7 here, `--fail-on banana` below)."""
    assert exit_code(session_with(state, tier), fail_on) == code


def test_unknown_fail_on_value_exits_3(capsys):
    """Scenario: Exit code matrix, `--fail-on banana`."""
    with pytest.raises(SystemExit) as raised:
        main(["--url", "https://example.com", "--yes", "--fail-on", "banana"])
    assert raised.value.code == 3
    assert "invalid severity" in capsys.readouterr().err


def test_unknown_option_exits_3():
    with pytest.raises(SystemExit) as raised:
        main(["--no-such-flag"])
    assert raised.value.code == 3


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Run the CLI with the given probes in place of the registered scanners."""
    saved: list[ScanSession] = []
    monkeypatch.setattr(
        "haris.cli._save_session_to_db", lambda s, **_k: saved.append(s)
    )
    monkeypatch.chdir(tmp_path)

    def run(probes: list[Probe], *flags: str) -> int:
        monkeypatch.setattr(ScanRunner, "_build_scanners", lambda _self: probes)
        return main(
            [
                "--url",
                "https://example.com",
                "--yes",
                "--formats",
                "json",
                "--output",
                str(tmp_path / "out"),
                "--verify",
                "off",
                *flags,
            ]
        )

    run.saved = saved  # type: ignore[attr-defined]
    return run


def test_scan_exit_codes_through_the_cli(scan):
    xss = finding("Reflected XSS", "https://example.com/s?q=1", "nuclei")
    assert scan([Probe("nuclei", findings=[xss])], "--fail-on", "high") == 1
    assert scan([Probe("nuclei", findings=[xss])]) == 0
    assert scan([Probe("nuclei", errors=["timed out"])]) == 2


def test_every_scanner_failing_exits_2_with_posture_unknown(scan, capsys):
    assert scan([Probe("wapiti", raises=RuntimeError("boom"))]) == 2
    assert "Risk posture: UNKNOWN" in capsys.readouterr().out


def test_partial_session_is_saved_without_credentials(scan, tmp_path):
    probes = [Probe("wapiti"), Probe("nuclei", errors=["timed out"])]
    scan(probes, "--parallel", "1")

    partial = json.loads((tmp_path / "out" / "session.partial.json").read_text())
    assert [r["scanner_name"] for r in partial["scanner_results"]] == [
        "wapiti",
        "nuclei",
    ]
    assert "auth" not in partial["target"]
    assert len(scan.saved) >= 3


def test_baseline_prints_changes_without_changing_exit_code(scan, tmp_path, capsys):
    xss = finding("Reflected XSS", "https://example.com/s?q=1", "nuclei")
    assert scan([Probe("nuclei", findings=[xss])]) == 0
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"meta": {}, "findings": [], "errors": []}))
    capsys.readouterr()

    assert scan([Probe("nuclei", findings=[xss])], "--baseline", str(baseline)) == 0
    out = capsys.readouterr().out
    assert "Changes since baseline" in out
    assert "1 new" in out


def test_unreadable_baseline_exits_3(scan, tmp_path):
    assert scan([Probe("nuclei")], "--baseline", str(tmp_path / "gone.json")) == 3


def test_declined_authorisation_exits_3(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "no")
    assert main(["--url", "https://example.com"]) == 3
