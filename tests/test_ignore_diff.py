import json
import logging
from datetime import date
from pathlib import Path

import pytest

from haris.cli import main
from haris.core.identity import assign_identity
from haris.diff import DiffStatus, diff_reports, load_report
from haris.ignore import IgnoreError, IgnoreFile, apply_ignores, load_ignore_file
from haris.models import (
    CorrelatedFinding,
    Finding,
    ScanSession,
    Severity,
    Suppression,
    Target,
    Verification,
    VerificationTier,
)

BASE = "https://example.com"
TODAY = date(2026, 11, 8)
STATIC = "https://example.com/static/app.js"
API = "https://example.com/api/**"


def make(url: str = STATIC, scanner: str = "header_checks", **extra: object) -> Finding:
    fields: dict[str, object] = {
        "title": "Missing X-Frame-Options header",
        "description": "",
        "severity": Severity.LOW,
        "vuln_class": "missing_header",
        "url": url,
        "scanner": scanner,
    }
    fields.update(extra)
    finding = Finding.model_validate(fields)
    assign_identity(finding, BASE)
    return finding


def ignore_file(**entry: object) -> IgnoreFile:
    base = {"reason": "accepted", "author": "qa", "expires": "2027-01-31"}
    return IgnoreFile.model_validate({"version": 1, "ignores": [{**base, **entry}]})


@pytest.mark.parametrize(
    ("entry", "suppressed"),
    [
        ({"rule": "missing_header", "url": "https://example.com/static/**"}, True),
        ({"rule": "missing_header", "url": API}, False),
        ({"rule": "missing_header"}, True),
        (
            {
                "rule": "missing_header",
                "url": "https://example.com/static/**",
                "expires": "2026-11-01",
            },
            False,
        ),
        ({"rule": "insecure_cookie"}, False),
    ],
)
def test_ignore_entry_evaluation(entry, suppressed):
    """Scenario: Ignore entry evaluation."""
    finding = make()
    apply_ignores([finding], ignore_file(**entry), base_url=BASE, today=TODAY)
    assert (finding.suppression is not None) is suppressed


def test_expired_entry_warns(caplog):
    with caplog.at_level(logging.WARNING):
        apply_ignores(
            [make()],
            ignore_file(rule="missing_header", expires="2026-11-01"),
            base_url=BASE,
            today=TODAY,
        )
    assert "expired" in caplog.text


def test_entry_valid_through_its_expiry_date():
    finding = make()
    entry = ignore_file(rule="missing_header", expires="2026-11-08")
    apply_ignores([finding], entry, base_url=BASE, today=TODAY)
    assert finding.suppression is not None


@pytest.mark.parametrize("tier", list(VerificationTier))
def test_suppression_applies_to_every_tier(tier):
    finding = make()
    finding.verification = Verification(tier=tier)
    apply_ignores(
        [finding], ignore_file(fingerprint=finding.fingerprint), base_url=BASE
    )
    assert finding.suppression is not None
    assert finding.suppression.reason == "accepted"


def test_fingerprint_entry_matches_only_that_finding():
    hit, other = make(), make(vuln_class="insecure_cookie")
    apply_ignores([hit, other], ignore_file(fingerprint=hit.fingerprint), base_url=BASE)
    assert hit.suppression is not None
    assert other.suppression is None


@pytest.mark.parametrize(
    "entry",
    [
        {"rule": "missing_header", "fingerprint": "a" * 64},
        {"fingerprint": "abc"},
        {"rule": "missing_header", "unknown": 1},
        {"fingerprint": "a" * 64, "url": "https://example.com/**"},
        {"rule": "missing_header", "expires": "soon"},
    ],
)
def test_invalid_entries_are_rejected(entry):
    with pytest.raises(ValueError, match="ignores"):
        ignore_file(**entry)


def test_entry_without_reason_exits_3_before_any_request(tmp_path, monkeypatch, capsys):
    """Scenario: Entry without reason."""
    path = tmp_path / "ignore.yaml"
    path.write_text(
        "version: 1\nignores:\n  - rule: missing_header\n"
        "    expires: 2027-01-31\n    author: qa\n"
    )
    with pytest.raises(IgnoreError, match="reason"):
        load_ignore_file(path)

    def no_scan(*_args, **_kwargs):
        raise AssertionError("a scan must not start")

    monkeypatch.setattr("haris.cli_scan.ScanRunner", no_scan)
    code = main(["--url", "https://example.com", "--yes", "--ignore-file", str(path)])
    assert code == 3
    assert "reason" in capsys.readouterr().err


def test_missing_explicit_ignore_file_exits_3(tmp_path):
    assert (
        main(["--url", "https://example.com", "--yes", "--ignore-file", "nope.yaml"])
        == 3
    )


# Diff


def write_report(
    path: Path,
    findings: list[tuple[Finding, str]],
    status: dict[str, str],
    tiers: dict[str, VerificationTier] | None = None,
) -> Path:
    items = []
    for finding, scanner in findings:
        if tiers and finding.title in tiers:
            finding.verification = Verification(tier=tiers[finding.title])
        items.append({**finding.to_dict(), "sources": [[scanner, "obs"]]})
    path.write_text(
        json.dumps(
            {
                "meta": {"scanners_used": list(status)},
                "correlated": items,
                "scanner_status": status,
            }
        )
    )
    return path


@pytest.mark.parametrize(
    ("wapiti_state", "b_class"),
    [("completed", "fixed"), ("failed", "not_retested")],
)
def test_diff_classes(tmp_path, capsys, wapiti_state, b_class):
    """Scenario: Diff classes (timed out is a failed scanner status)."""
    a = make(url="https://example.com/a", title="A", scanner="nuclei")
    b = make(url="https://example.com/b", title="B", scanner="wapiti")
    c = make(url="https://example.com/c", title="C", scanner="nuclei")
    old = write_report(
        tmp_path / "old.json",
        [(a, "nuclei"), (b, "wapiti")],
        {"nuclei": "completed", "wapiti": "completed"},
    )
    new = write_report(
        tmp_path / "new.json",
        [(a, "nuclei"), (c, "nuclei")],
        {"nuclei": "completed", "wapiti": wapiti_state},
        tiers={"A": VerificationTier.REPLAY_VERIFIED},
    )

    assert main(["diff", str(old), str(new)]) == 0
    out = capsys.readouterr().out

    status = {
        e.title: e.status for e in diff_reports(load_report(old), load_report(new))
    }
    assert status == {
        "A": DiffStatus.UNCHANGED,
        "B": DiffStatus(b_class),
        "C": DiffStatus.NEW,
    }
    assert "unverified -> replay_verified" in out
    assert f"1 {b_class}" in out


def test_diff_of_unreadable_report_exits_3(tmp_path):
    assert main(["diff", str(tmp_path / "x.json"), str(tmp_path / "y.json")]) == 3


def test_diff_accepts_a_0_6_2_report(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "report_0_6_2.json"
    report = load_report(fixture)
    assert report.findings
    assert "nuclei" not in report.completed
    assert "nmap" in report.completed
    assert all(e.status is DiffStatus.UNCHANGED for e in diff_reports(report, report))


# Visibility (JSON/Markdown rendering belongs to reporting; this is the data it reads)


@pytest.mark.parametrize(
    ("tier", "suppressed", "appendix"),
    [
        (VerificationTier.UNVERIFIED, False, False),
        (VerificationTier.REPLAY_VERIFIED, False, False),
        (VerificationTier.EXPLOIT_VALIDATED, False, False),
        (VerificationTier.REFUTED, False, True),
        (VerificationTier.REPLAY_VERIFIED, True, True),
    ],
)
def test_visibility_by_tier(tier, suppressed, appendix):
    """Scenario: Visibility by tier (report data half)."""
    finding = make()
    finding.verification = Verification(tier=tier)
    if suppressed:
        finding.suppression = Suppression(reason="r", author="a", expires="2027-01-31")
    session = ScanSession(
        session_id="s",
        target=Target(base_url=BASE),
        correlated=[CorrelatedFinding(canonical=finding, sources=[("x", "o")])],
    )
    extras = session.report_extras()
    assert extras["correlated"][0]["fingerprint"] == finding.fingerprint
    assert extras["correlated"][0]["verification"]["tier"] == tier.value
    assert finding.is_active is (not appendix)
