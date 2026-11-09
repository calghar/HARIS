import json
from pathlib import Path
from typing import Any

import pytest

from haris.bench.__main__ import main
from haris.bench.score import load_reports, score_run, score_runs
from haris.bench.truth import (
    GroundTruth,
    IgnoreEntry,
    TruthEntry,
    normalise_cwe,
    normalise_path,
)
from haris.cli import main as haris_main
from haris.core.exit_codes import EXIT_USAGE

ENTRIES = [
    ("sqli", "/rest/search", "q", "sqli_error", "CWE-89"),
    ("xss", "/page/a", "name", "xss_reflected", "CWE-79"),
    ("csrf", "/page/b", "token", "csrf", "CWE-352"),
    ("exec", "/page/c", "ip", "command_injection", "CWE-78"),
]
TRUTH = GroundTruth(
    target="unit",
    kind="fixture",
    entries=[
        TruthEntry(
            id=entry_id,
            method="GET",
            url=url,
            parameter=parameter,
            vuln_class=vuln_class,
            cwe=cwe,
            expected="true_positive",
        )
        for entry_id, url, parameter, vuln_class, cwe in ENTRIES
    ],
)


def finding(
    vuln_class: str, url: str, parameter: str = "", **extra: Any
) -> dict[str, Any]:
    return {"vuln_class": vuln_class, "url": url, "parameter": parameter, **extra}


TP = {
    "sqli": finding("sqli_error", "http://t:1/rest/search", "q"),
    "xss": finding("xss_reflected", "http://t:1/page/a", "name"),
    "csrf": finding("csrf", "http://t:1/page/b", "token"),
    "exec": finding("command_injection", "http://t:1/page/c", "ip"),
}
FP = [
    finding("missing_header", "http://t:1/"),
    finding("sqli_error", "http://t:1/rest/other", "q"),
    finding("xss_reflected", "http://t:1/page/a", "other"),
]


def report(findings: list[dict[str, Any]], **meta: Any) -> dict[str, Any]:
    return {"meta": meta, "findings": findings}


class TestScoreRun:
    def test_all_true_positives(self) -> None:
        score = score_run(report(list(TP.values())), TRUTH)
        assert (score.true_positives, score.false_positives, score.false_negatives) == (
            4,
            0,
            0,
        )
        assert (score.precision, score.recall, score.f1) == (1.0, 1.0, 1.0)

    def test_all_false_positives(self) -> None:
        score = score_run(report(FP), TRUTH)
        assert (score.true_positives, score.false_positives, score.false_negatives) == (
            0,
            3,
            4,
        )
        assert (score.precision, score.recall, score.f1) == (0.0, 0.0, 0.0)

    def test_mixed_findings(self) -> None:
        score = score_run(report([TP["sqli"], TP["xss"], FP[0]]), TRUTH)
        assert (score.true_positives, score.false_positives, score.false_negatives) == (
            2,
            1,
            2,
        )
        assert score.precision == pytest.approx(2 / 3)
        assert score.recall == 0.5
        assert score.f1 == pytest.approx(4 / 7)
        assert score.true_positive_rate == score.recall

    def test_empty_report_has_vacuous_precision_and_zero_recall(self) -> None:
        score = score_run(report([]), TRUTH)
        assert (score.findings, score.false_negatives) == (0, 4)
        assert (score.precision, score.recall, score.f1) == (1.0, 0.0, 0.0)

    def test_empty_truth_makes_every_finding_a_false_positive(self) -> None:
        truth = GroundTruth(target="spa", kind="fixture", entries=[])
        trap = score_run(report([finding("sensitive_file", "http://t:1/.env")]), truth)
        assert (trap.false_positives, trap.precision, trap.recall) == (1, 0.0, 1.0)
        clean = score_run(report([]), truth)
        assert (clean.false_positives, clean.precision, clean.recall) == (0, 1.0, 1.0)

    def test_ignored_findings_leave_precision_and_recall_unchanged(self) -> None:
        truth = TRUTH.model_copy(
            update={
                "ignore": [
                    IgnoreEntry(vuln_class="sensitive_file", url="/health", reason="r"),
                    IgnoreEntry(
                        vuln_class="info", url="/disc/*", parameter="p", reason="r"
                    ),
                ]
            }
        )
        noise = [
            finding("sensitive_file", "http://t:1/health"),
            finding("info", "http://t:1/disc/a", "p"),
            finding("info", "http://t:1/disc/b", "p"),
        ]
        score = score_run(report([TP["sqli"], FP[0], *noise]), truth)
        assert (score.findings, score.ignored) == (2, 3)
        assert (score.true_positives, score.false_positives) == (1, 1)
        assert (score.precision, score.recall) == (0.5, 0.25)

    def test_ignore_without_parameter_matches_any_parameter_only_on_its_path(
        self,
    ) -> None:
        truth = TRUTH.model_copy(
            update={"ignore": [IgnoreEntry(vuln_class="info", url="/disc", reason="r")]}
        )
        hits = [finding("info", "http://t:1/disc", "a")]
        misses = [finding("info", "http://t:1/other", "a")]
        assert score_run(report(hits), truth).ignored == 1
        assert score_run(report(misses), truth).ignored == 0

    def test_duplicate_findings_count_once(self) -> None:
        duplicates = [
            TP["sqli"],
            finding("sqli_error", "https://other:9/rest/search/?q=1", "q"),
            finding("sqli_error", "http://t:1/rest//search", "q", scanner="nuclei"),
            FP[0],
            FP[0],
        ]
        score = score_run(report(duplicates), TRUTH)
        assert (score.findings, score.true_positives, score.false_positives) == (
            2,
            1,
            1,
        )
        assert score.precision == 0.5

    def test_cwe_matches_when_finding_has_no_vuln_class(self) -> None:
        cwe_only = {"cwe_id": "89", "url": "http://t:1/rest/search", "parameter": "q"}
        assert score_run(report([cwe_only]), TRUTH).true_positives == 1

    def test_wrong_parameter_is_not_a_match(self) -> None:
        wrong = finding("sqli_error", "http://t:1/rest/search", "id")
        assert score_run(report([wrong]), TRUTH).true_positives == 0

    def test_url_glob_in_truth_matches_path_segments(self) -> None:
        truth = GroundTruth(
            target="glob",
            kind="fixture",
            entries=[
                TruthEntry(
                    id="g",
                    method="GET",
                    url="/api/*/items/",
                    vuln_class="sqli_error",
                    cwe="CWE-89",
                    expected="true_positive",
                )
            ],
        )
        hit = finding("sqli_error", "http://t:1/api/v2/items")
        assert score_run(report([hit]), truth).true_positives == 1

    def test_run_metadata_is_read_from_meta(self) -> None:
        meta = {"request_count": 120, "cost_usd": 0.5, "duration_seconds": 42.5}
        score = score_run(report([], **meta), TRUTH)
        assert (score.request_count, score.cost_usd, score.wall_time_s) == (
            120,
            0.5,
            42.5,
        )
        bare = score_run(report([]), TRUTH)
        assert (bare.request_count, bare.cost_usd, bare.wall_time_s) == (
            None,
            None,
            None,
        )


class TestScoreRuns:
    def test_mean_and_sample_stddev_across_runs(self) -> None:
        reports = [
            ("r1", report(list(TP.values()), request_count=100, duration_seconds=10)),
            (
                "r2",
                report([TP["sqli"], TP["xss"]], request_count=200, duration_seconds=20),
            ),
            ("r3", report([], request_count=300, duration_seconds=30)),
        ]
        summary = score_runs(reports, TRUTH).summary
        recall, requests, wall = (
            summary["recall"],
            summary["request_count"],
            summary["wall_time_s"],
        )
        assert recall and requests and wall
        assert (recall.mean, recall.stddev, recall.n) == (0.5, 0.5, 3)
        assert (requests.mean, requests.stddev) == (200.0, 100.0)
        assert (wall.mean, wall.stddev) == (20.0, 10.0)
        assert summary["cost_usd"] is None

    def test_single_run_has_zero_stddev(self) -> None:
        summary = score_runs([("r1", report([TP["sqli"]]))], TRUTH).summary
        precision = summary["precision"]
        assert precision and (precision.mean, precision.stddev, precision.n) == (
            1.0,
            0.0,
            1,
        )

    def test_fp_reduction_is_relative_to_baseline_mean(self) -> None:
        baseline = [
            ("b1", report(FP + [TP["csrf"]])),
            ("b2", report(FP + [TP["exec"]])),
        ]
        runs = score_runs([("r1", report([TP["sqli"], FP[0]]))], TRUTH, baseline)
        assert runs.baseline_runs == 2
        assert runs.runs[0].fp_reduction_rate == pytest.approx(1 - 1 / 3)

    def test_fp_reduction_is_undefined_when_baseline_has_no_false_positives(
        self,
    ) -> None:
        baseline = [("b1", report([TP["sqli"]]))]
        runs = score_runs([("r1", report([FP[0]]))], TRUTH, baseline)
        assert runs.runs[0].fp_reduction_rate is None


class TestLoading:
    def test_directory_holds_one_report_per_run(self, tmp_path: Path) -> None:
        for index in (2, 1):
            (tmp_path / f"run{index}.json").write_text(json.dumps(report([])))
        assert [name for name, _ in load_reports(tmp_path)] == [
            "run1.json",
            "run2.json",
        ]

    def test_non_report_json_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"hello": 1}))
        with pytest.raises(ValueError, match="no findings list"):
            load_reports(bad)

    def test_empty_directory_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="no reports found"):
            load_reports(tmp_path)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("79", "CWE-79"), ("cwe-79", "CWE-79"), (79, "CWE-79"), ("", ""), ("n/a", "")],
    )
    def test_cwe_normalisation(self, raw: object, expected: str) -> None:
        assert normalise_cwe(raw) == expected

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("http://h:1/a/b/?x=1#f", "/a/b"),
            ("/a//b", "/a/b"),
            ("http://h", "/"),
            ("/a%20b", "/a b"),
        ],
    )
    def test_path_normalisation(self, url: str, expected: str) -> None:
        assert normalise_path(url) == expected


class TestCli:
    def test_score_writes_json_and_markdown(self, tmp_path: Path) -> None:
        runs = tmp_path / "runs"
        runs.mkdir()
        (runs / "run1.json").write_text(json.dumps(report(list(TP.values()))))
        truth_file = tmp_path / "truth.yaml"
        truth_file.write_text(
            "target: unit\nkind: fixture\nentries:\n"
            "  - {id: a, method: GET, url: /rest/search, parameter: q,"
            " vuln_class: sqli_error, cwe: CWE-89, expected: true_positive}\n"
        )
        assert main(["score", str(runs), str(truth_file)]) == 0
        scored = json.loads((runs / "score" / "score.json").read_text())
        assert scored["target"] == "unit"
        assert scored["runs"][0]["false_positives"] == 3
        assert "# Benchmark score: unit" in (runs / "score" / "score.md").read_text()

    def test_ignored_count_is_written_to_json_and_markdown(
        self, tmp_path: Path
    ) -> None:
        runs = tmp_path / "runs"
        runs.mkdir()
        (runs / "run1.json").write_text(
            json.dumps(report([finding("sensitive_file", "http://t:1/health")]))
        )
        truth_file = tmp_path / "truth.yaml"
        truth_file.write_text(
            "target: unit\nkind: fixture\nentries: []\nignore:\n"
            "  - {vuln_class: sensitive_file, url: /health, reason: liveness path}\n"
        )
        assert main(["score", str(runs), str(truth_file)]) == 0
        scored = json.loads((runs / "score" / "score.json").read_text())
        assert (scored["runs"][0]["ignored"], scored["runs"][0]["findings"]) == (1, 0)
        markdown = (runs / "score" / "score.md").read_text()
        assert "| Ignored |" in markdown
        assert "| run1.json | 0 | 1 | 0 | 0 | 0 |" in markdown


class TestHarisBenchCli:
    @staticmethod
    def _inputs(tmp_path: Path) -> tuple[Path, Path]:
        runs = tmp_path / "runs"
        runs.mkdir()
        (runs / "run1.json").write_text(json.dumps(report(list(TP.values()))))
        truth_file = tmp_path / "truth.yaml"
        truth_file.write_text(
            "target: unit\nkind: fixture\nentries:\n"
            "  - {id: a, method: GET, url: /rest/search, parameter: q,"
            " vuln_class: sqli_error, cwe: CWE-89, expected: true_positive}\n"
        )
        return runs, truth_file

    def test_prints_the_same_table_as_python_m(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runs, truth_file = self._inputs(tmp_path)
        assert main(["score", str(runs), str(truth_file)]) == 0
        expected = capsys.readouterr().out
        assert haris_main(["bench", "score", str(runs), str(truth_file)]) == 0
        assert capsys.readouterr().out == expected

    def test_baseline_is_forwarded(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runs, truth_file = self._inputs(tmp_path)
        argv = ["bench", "score", str(runs), str(truth_file), "--baseline", str(runs)]
        assert haris_main(argv) == 0
        assert (
            json.loads((runs / "score" / "score.json").read_text())["baseline_runs"]
            == 1
        )

    def test_missing_path_exits_usage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runs, truth_file = self._inputs(tmp_path)
        missing = str(tmp_path / "nope")
        assert haris_main(["bench", "score", missing, str(truth_file)]) == EXIT_USAGE
        assert haris_main(["bench", "score", str(runs), missing]) == EXIT_USAGE
        assert "Error:" in capsys.readouterr().err

    def test_help_lists_bench(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exit_info:
            haris_main(["--help"])
        assert exit_info.value.code == 0
        assert "bench" in capsys.readouterr().out
