import json
import statistics
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..models import VerificationTier
from .truth import GroundTruth, normalise_cwe, normalise_path

METRICS = (
    "precision",
    "verified_precision",
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
    ignored: int = 0
    refuted: int = 0
    refuted_true_positives: int = 0
    unverified: int = 0
    verified: int = 0
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    verified_precision: float | None = None
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


type Key = tuple[str, str, str]


def _strength(tier: VerificationTier) -> int:
    return -1 if tier is VerificationTier.REFUTED else tier.rank


def key_tiers(report: dict[str, Any]) -> dict[Key, VerificationTier]:
    """Tier per finding key: the strongest non-refuted tier, else refuted."""
    tiers: dict[Key, VerificationTier] = {}
    for finding in report.get("findings", []):
        tier = VerificationTier(
            (finding.get("verification") or {}).get("tier", VerificationTier.UNVERIFIED)
        )
        key = finding_key(finding)
        if key not in tiers or _strength(tier) > _strength(tiers[key]):
            tiers[key] = tier
    return tiers


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
    """Precision covers active (non-refuted) findings; recall covers all of them.

    Precision is 1.0 with no active findings and recall 1.0 with no truth (vacuous);
    `verified_precision` is None with no verified findings. Findings matching a
    truth `ignore` entry are excluded before scoring.
    """
    tiers = key_tiers(report)
    keys = {k for k in tiers if not any(i.matches(*k) for i in truth.ignore)}
    matched_entries: set[str] = set()
    is_true = {k: False for k in keys}
    for key in keys:
        hits = [entry.id for entry in truth.entries if entry.matches(*key)]
        matched_entries.update(hits)
        is_true[key] = bool(hits)
    refuted = {k for k in keys if tiers[k] is VerificationTier.REFUTED}
    active = keys - refuted
    verified = {k for k in active if tiers[k] is not VerificationTier.UNVERIFIED}
    true_positives = sum(is_true[k] for k in active)
    false_positives = len(active) - true_positives
    false_negatives = len(truth.entries) - len(matched_entries)
    precision = _ratio(true_positives, len(active), 1.0)
    recall = _ratio(len(matched_entries), len(truth.entries), 1.0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    meta = report.get("meta", {})
    reduction = None
    if baseline_fp:
        reduction = (baseline_fp - false_positives) / baseline_fp
    return RunScore(
        source=source,
        findings=len(keys),
        ignored=len(tiers) - len(keys),
        refuted=len(refuted),
        refuted_true_positives=sum(is_true[k] for k in refuted),
        unverified=len(active) - len(verified),
        verified=len(verified),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        verified_precision=(
            sum(is_true[k] for k in verified) / len(verified) if verified else None
        ),
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
