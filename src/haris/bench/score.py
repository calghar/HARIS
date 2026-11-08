import json
import statistics
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .truth import GroundTruth, normalise_cwe, normalise_path

METRICS = (
    "precision",
    "recall",
    "f1",
    "true_positive_rate",
    "fp_reduction_rate",
    "request_count",
    "cost_usd",
    "wall_time_s",
)


class RunScore(BaseModel):
    source: str = ""
    findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    true_positive_rate: float
    fp_reduction_rate: float | None = None
    request_count: float | None = None
    cost_usd: float | None = None
    wall_time_s: float | None = None


class Stat(BaseModel):
    mean: float
    stddev: float
    n: int


class BenchScore(BaseModel):
    target: str
    runs: list[RunScore]
    summary: dict[str, Stat | None]
    baseline_runs: int = 0


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    """(class token, normalised path, parameter); the token falls back to the CWE."""
    token = str(finding.get("vuln_class") or "") or normalise_cwe(finding.get("cwe_id"))
    return (
        token,
        normalise_path(str(finding.get("url", ""))),
        str(finding.get("parameter") or ""),
    )


def unique_finding_keys(report: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {finding_key(finding) for finding in report.get("findings", [])}


def _ratio(numerator: int, denominator: int, empty: float) -> float:
    return numerator / denominator if denominator else empty


def _optional_number(meta: dict[str, Any], key: str) -> float | None:
    value = meta.get(key)
    return float(value) if isinstance(value, int | float) else None


def score_run(
    report: dict[str, Any],
    truth: GroundTruth,
    *,
    source: str = "",
    baseline_fp: float | None = None,
) -> RunScore:
    """Precision is 1.0 with no findings and recall 1.0 with no truth (vacuous)."""
    keys = unique_finding_keys(report)
    matched_entries: set[str] = set()
    true_positives = 0
    for key in keys:
        hits = [entry.id for entry in truth.entries if entry.matches(*key)]
        matched_entries.update(hits)
        true_positives += bool(hits)
    false_positives = len(keys) - true_positives
    false_negatives = len(truth.entries) - len(matched_entries)
    precision = _ratio(true_positives, len(keys), 1.0)
    recall = _ratio(len(matched_entries), len(truth.entries), 1.0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    meta = report.get("meta", {})
    reduction = None
    if baseline_fp:
        reduction = (baseline_fp - false_positives) / baseline_fp
    return RunScore(
        source=source,
        findings=len(keys),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        true_positive_rate=recall,
        fp_reduction_rate=reduction,
        request_count=_optional_number(meta, "request_count"),
        cost_usd=_optional_number(meta, "cost_usd"),
        wall_time_s=_optional_number(meta, "duration_seconds"),
    )


def summarise(runs: list[RunScore]) -> dict[str, Stat | None]:
    """Mean and sample stddev per metric over runs that report it (0 for one run)."""
    summary: dict[str, Stat | None] = {}
    for metric in METRICS:
        values = [v for run in runs if (v := getattr(run, metric)) is not None]
        summary[metric] = (
            Stat(
                mean=statistics.fmean(values),
                stddev=statistics.stdev(values) if len(values) > 1 else 0.0,
                n=len(values),
            )
            if values
            else None
        )
    return summary


def load_reports(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """A report file is one run; a directory holds one `*.json` report per run."""
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    reports = [(file.name, json.loads(file.read_text())) for file in files]
    for name, report in reports:
        if not isinstance(report.get("findings"), list):
            raise ValueError(f"{name}: not a HARIS JSON report (no findings list)")
    if not reports:
        raise ValueError(f"{path}: no reports found")
    return reports


def score_runs(
    reports: list[tuple[str, dict[str, Any]]],
    truth: GroundTruth,
    baseline: list[tuple[str, dict[str, Any]]] | None = None,
) -> BenchScore:
    baseline_fp = None
    if baseline:
        baseline_fp = statistics.fmean(
            score_run(report, truth).false_positives for _, report in baseline
        )
    runs = [
        score_run(report, truth, source=name, baseline_fp=baseline_fp)
        for name, report in reports
    ]
    return BenchScore(
        target=truth.target,
        runs=runs,
        summary=summarise(runs),
        baseline_runs=len(baseline or []),
    )
