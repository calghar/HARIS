import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from haris.bench.truth import GroundTruth, IgnoreEntry, TruthEntry, load_ground_truth

CALIBRATE_PY = Path(__file__).resolve().parent.parent / "bench" / "calibrate_abstain.py"
MODEL = "bedrock/anthropic.claude-sonnet-4-5"
GRID = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]
TRUTH = GroundTruth(
    target="unit",
    kind="fixture",
    entries=[
        TruthEntry(
            id="sqli-rest",
            method="GET",
            url="/rest/*",
            vuln_class="sqli_error",
            cwe="CWE-89",
            expected="true_positive",
        )
    ],
    ignore=[IgnoreEntry(vuln_class="no_https", url="/*", reason="plain HTTP")],
)


def load_calibrator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench_calibrate", CALIBRATE_PY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


calibrator = load_calibrator()


def verdict_row(label: bool, confidence: float, verdict: str = "confirmed") -> dict:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "label": label,
        "status": "ok",
        "model": MODEL,
    }


def confirmed_rows(count: int, hits: int, confidence: float) -> list[dict]:
    return [verdict_row(i < hits, confidence) for i in range(count)]


def regional_rows(c_low: int, c_mid: int, c_high: int) -> list[dict]:
    """20 rows at each of 0.95, 0.85, 0.65: 20, 40, 60 confirmed at 0.9, 0.7, 0.5."""
    rows: list[dict] = []
    hits_so_far = 0
    for cumulative_hits, confidence in (
        (c_high, 0.95),
        (c_mid, 0.85),
        (c_low, 0.65),
    ):
        rows += confirmed_rows(20, cumulative_hits - hits_so_far, confidence)
        hits_so_far = cumulative_hits
    return rows


def report_finding(
    finding_id: str, vuln_class: str, url: str, **llm: Any
) -> dict[str, Any]:
    fields = {"verdict": "confirmed", "confidence": 0.9, "status": "ok", "model": MODEL}
    return {
        "finding_id": finding_id,
        "vuln_class": vuln_class,
        "url": url,
        "parameter": "",
        "verification": {"tier": "unverified", "llm": {**fields, **llm}},
    }


@pytest.mark.parametrize(
    ("c_low", "c_mid", "c_high", "default", "calibrated"),
    [
        (55, 39, 20, 0.5, True),
        (52, 40, 20, 0.7, True),
        (50, 34, 20, 0.9, True),
        (50, 34, 19, 0.7, False),
    ],
)
def test_threshold_selection(
    c_low: int, c_mid: int, c_high: int, default: float, calibrated: bool
) -> None:
    choice = calibrator.choose_threshold(regional_rows(c_low, c_mid, c_high))
    assert [p["confirmed"] for p in choice["grid"]] == [60] * 4 + [40] * 4 + [20] * 2
    assert [p["true_positives"] for p in choice["grid"]] == (
        [c_low] * 4 + [c_mid] * 4 + [c_high] * 2
    )
    assert choice["default"] == default
    assert choice["calibrated"] is calibrated


@pytest.mark.parametrize(
    ("count", "default", "calibrated"),
    [(16, 0.5, True), (15, 0.7, False), (0, 0.7, False)],
)
def test_too_few_confirmed_verdicts(
    count: int, default: float, calibrated: bool
) -> None:
    choice = calibrator.choose_threshold(confirmed_rows(count, count, 0.95))
    assert [p["confirmed"] for p in choice["grid"]] == [count] * 10
    assert [p["precision"] for p in choice["grid"]] == [1.0 if count else None] * 10
    assert choice["default"] == default
    assert choice["calibrated"] is calibrated


@pytest.mark.parametrize(
    ("count", "hits", "bound", "reaches"),
    [
        (16, 16, 0.806, True),
        (15, 15, 0.796, False),
        (9, 9, 0.701, False),
        (9, 7, 0.453, False),
        (0, 0, None, False),
    ],
)
def test_lower_bound_target_is_compared_unrounded(
    count: int, hits: int, bound: float | None, reaches: bool
) -> None:
    point = calibrator.choose_threshold(confirmed_rows(count, hits, 0.95))["grid"][0]
    assert point["lower_bound"] == bound
    assert point["reaches"] is reaches


@pytest.mark.parametrize(
    ("confidence", "grid_points"), [(0.55, 2), (0.7, 5), (0.85, 8), (0.95, 10)]
)
def test_verdict_counts_at_every_grid_point_up_to_its_confidence(
    confidence: float, grid_points: int
) -> None:
    grid = calibrator.choose_threshold([verdict_row(True, confidence)])["grid"]
    assert [p["threshold"] for p in grid if p["confirmed"]] == GRID[:grid_points]


def test_only_confirmed_verdicts_count_toward_precision() -> None:
    rows = confirmed_rows(16, 16, 0.9) + [
        verdict_row(False, 0.9, "likely_fp"),
        verdict_row(False, 0.9, "inconclusive"),
    ]
    choice = calibrator.choose_threshold(rows)
    assert choice["grid"][0]["confirmed"] == 16
    assert choice["default"] == 0.5


def test_labels_follow_truth_and_ignored_findings_are_dropped() -> None:
    findings = [
        report_finding("f-1", "sqli_error", "http://t:1/rest/search"),
        report_finding("f-2", "xss_reflected", "http://t:1/page/a"),
        report_finding("f-3", "no_https", "http://t:1/"),
        report_finding("f-4", "sqli_error", "http://t:1/rest/search", confidence=0.8),
        {"finding_id": "f-5", "vuln_class": "csrf", "url": "http://t:1/form"},
    ]
    rows, excluded = calibrator.report_cases(
        "unit", "stamp/runs/run1", {"findings": findings}, TRUTH
    )
    assert [(r["finding_id"], r["label"], r["key"]) for r in rows] == [
        ("f-1", True, ["sqli_error", "/rest/search", ""]),
        ("f-2", False, ["xss_reflected", "/page/a", ""]),
    ]
    assert not excluded


@pytest.mark.parametrize(
    ("status", "used"),
    [("ok", True), ("abstained", True), ("invalid", False), ("skipped_budget", False)],
)
def test_only_ok_and_abstained_statuses_become_cases(status: str, used: bool) -> None:
    finding = report_finding("f-1", "sqli_error", "http://t:1/rest/a", status=status)
    rows, excluded = calibrator.report_cases(
        "unit", "stamp/runs/run1", {"findings": [finding]}, TRUTH
    )
    assert len(rows) == used
    assert dict(excluded) == ({} if used else {status: 1})


def test_abstained_confirmed_verdicts_supply_the_region_below_the_old_default() -> None:
    findings = [
        report_finding(
            f"f-{i}",
            "sqli_error",
            f"http://t:1/rest/item{i}",
            confidence=0.62,
            status="abstained",
        )
        for i in range(16)
    ]
    rows, _ = calibrator.report_cases("unit", "r", {"findings": findings}, TRUTH)
    choice = calibrator.choose_threshold(rows)
    assert (choice["default"], choice["calibrated"]) == (0.5, True)
    assert choice["grid"][4]["confirmed"] == 0


def test_glob_truth_entry_labels_the_nikto_robots_finding_true() -> None:
    slug = (
        "unclassified:nikto:robots-txt-entry-ftp-is-returned-"
        "a-non-forbidden-or-redirect-http-code-200"
    )
    truth = load_ground_truth(CALIBRATE_PY.parent / "ground_truth" / "juice_shop.yaml")
    finding = report_finding("f-1", slug, "http://t:1/ftp/")
    rows, _ = calibrator.report_cases("juice_shop", "r", {"findings": [finding]}, truth)
    assert [(r["label"], r["key"]) for r in rows] == [(True, [slug, "/ftp", ""])]


def write_report(path: Path, findings: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"findings": findings}))


def synthetic_findings() -> list[dict[str, Any]]:
    true_positives = [
        report_finding(f"tp-{i}", "sqli_error", f"http://t:1/rest/item{i}")
        for i in range(12)
    ]
    return [
        *true_positives,
        report_finding(
            "fp-1",
            "xss_reflected",
            "http://t:1/page/a",
            confidence=0.6,
            status="abstained",
        ),
        report_finding("fp-2", "csrf", "http://t:1/form", status="skipped_budget"),
    ]


@pytest.fixture
def synthetic(tmp_path: Path) -> tuple[list[str], Path]:
    folders = []
    for stamp in ("2026-11-10-100000", "2026-11-11-100000"):
        runs = tmp_path / "results" / stamp / "unit"
        write_report(runs / "runs" / "run1.json", synthetic_findings())
        folders += ["--results", str(tmp_path / "results" / stamp)]
    first = tmp_path / "results" / "2026-11-10-100000" / "unit"
    write_report(first / "baseline" / "run1.json", [{"url": "/x"}])
    write_report(first / "raw" / "runs" / "run1" / "report.json", [])
    write_report(first / "runs" / "score" / "score.json", [])
    truth_dir = tmp_path / "truth"
    truth_dir.mkdir()
    (truth_dir / "unit.yaml").write_text(yaml.safe_dump(TRUTH.model_dump(mode="json")))
    return [*folders, "--truth-dir", str(truth_dir)], tmp_path / "out"


def test_end_to_end_run_writes_both_artifacts(
    synthetic: tuple[list[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    argv, out = synthetic
    assert calibrator.main([*argv, "--out", str(out)]) == 0
    assert capsys.readouterr().out == "default 0.65 calibrated True\n"
    verdicts = json.loads((out / "verdicts.json").read_text())
    abstain = json.loads((out / "abstain.json").read_text())
    assert verdicts["models"] == [MODEL]
    assert len(verdicts["rows"]) == 26
    assert len({(r["run"], r["finding_id"]) for r in verdicts["rows"]}) == 26
    assert {r["run"] for r in verdicts["rows"]} == {
        "2026-11-10-100000/runs/run1",
        "2026-11-11-100000/runs/run1",
    }
    assert abstain["models"] == [MODEL]
    assert abstain["cases"] == 26
    assert abstain["excluded"] == {"skipped_budget": 2}
    assert (abstain["default"], abstain["calibrated"]) == (0.65, True)
    assert abstain["grid"][2] == {
        "threshold": 0.6,
        "confirmed": 26,
        "true_positives": 24,
        "precision": 0.92,
        "lower_bound": 0.759,
        "reaches": False,
    }
    assert abstain["grid"][3]["reaches"] is True


@pytest.mark.parametrize("existing", ["verdicts.json", "abstain.json"])
def test_existing_output_file_is_never_overwritten(
    synthetic: tuple[list[str], Path], existing: str
) -> None:
    argv, out = synthetic
    out.mkdir()
    (out / existing).write_text("kept")
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        calibrator.main([*argv, "--out", str(out)])
    assert [p.name for p in out.iterdir()] == [existing]
    assert (out / existing).read_text() == "kept"


def test_target_without_ground_truth_is_refused(
    synthetic: tuple[list[str], Path], tmp_path: Path
) -> None:
    argv, out = synthetic
    (tmp_path / "truth" / "unit.yaml").unlink()
    with pytest.raises(SystemExit, match="no ground truth for unit"):
        calibrator.main([*argv, "--out", str(out)])
    assert not out.exists()
