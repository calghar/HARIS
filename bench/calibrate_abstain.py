import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from math import sqrt
from pathlib import Path
from typing import Any

from haris.bench.score import finding_key, load_reports
from haris.bench.truth import GroundTruth, load_ground_truth
from haris.models.verification import LLMAssessment

BENCH_DIR = Path(__file__).resolve().parent
TRUTH_DIR = BENCH_DIR / "ground_truth"
CALIBRATION_DIR = BENCH_DIR / "results" / "calibration"
STAMP = "%Y-%m-%d-%H%M%S"
OUTPUT_FILES = ("verdicts.json", "abstain.json")
GRID_HUNDREDTHS = range(50, 100, 5)
WILSON_Z = 1.96
MIN_LOWER_BOUND = 0.80
UNCALIBRATED_DEFAULT = 0.7
USED_STATUSES = ("ok", "abstained")

type Row = dict[str, Any]


def wilson_lower_bound(hits: int, total: int) -> float | None:
    """Lower end of the Wilson score interval of hits/total at 95% confidence."""
    if not total:
        return None
    p = hits / total
    z2 = WILSON_Z**2
    margin = WILSON_Z * sqrt(p * (1 - p) / total + z2 / (4 * total**2))
    return (p + z2 / (2 * total) - margin) / (1 + z2 / total)


def choose_threshold(rows: list[Row]) -> dict[str, Any]:
    """Lowest grid point whose confirmed precision has a lower bound of 0.80."""
    grid = []
    for hundredths in GRID_HUNDREDTHS:
        confirmed = [
            row
            for row in rows
            if row["verdict"] == "confirmed"
            and round(row["confidence"] * 100, 6) >= hundredths
        ]
        hits = sum(bool(row["label"]) for row in confirmed)
        bound = wilson_lower_bound(hits, len(confirmed))
        grid.append(
            {
                "threshold": hundredths / 100,
                "confirmed": len(confirmed),
                "true_positives": hits,
                "precision": round(hits / len(confirmed), 2) if confirmed else None,
                "lower_bound": None if bound is None else round(bound, 3),
                "reaches": bound is not None and bound >= MIN_LOWER_BOUND,
            }
        )
    reached = [point["threshold"] for point in grid if point["reaches"]]
    return {
        "grid": grid,
        "default": reached[0] if reached else UNCALIBRATED_DEFAULT,
        "calibrated": bool(reached),
    }


def report_cases(
    target: str, run: str, report: dict[str, Any], truth: GroundTruth
) -> tuple[list[Row], Counter[str]]:
    rows: list[Row] = []
    excluded: Counter[str] = Counter()
    seen: set[tuple[str, str, str]] = set()
    for finding in report["findings"]:
        raw = (finding.get("verification") or {}).get("llm")
        key = finding_key(finding)
        if not raw or key in seen or any(i.matches(*key) for i in truth.ignore):
            continue
        seen.add(key)
        llm = LLMAssessment.model_validate(raw)
        if llm.status not in USED_STATUSES:
            excluded[llm.status] += 1
            continue
        rows.append(
            {
                "target": target,
                "run": run,
                "finding_id": finding.get("finding_id", ""),
                "key": list(key),
                "verdict": llm.verdict,
                "confidence": llm.confidence,
                "status": llm.status,
                "label": any(entry.matches(*key) for entry in truth.entries),
                "model": llm.model,
            }
        )
    return rows, excluded


def collect_cases(
    folders: list[Path], truth_dir: Path
) -> tuple[list[Row], Counter[str]]:
    """Cases of every `<folder>/<target>/<label>/run<N>.json` report."""
    rows: list[Row] = []
    excluded: Counter[str] = Counter()
    truths: dict[str, GroundTruth] = {}
    for folder in folders:
        for label_dir in sorted(folder.glob("*/*")):
            if not any(label_dir.glob("run*.json")):
                continue
            target = label_dir.parent.name
            if target not in truths:
                truth_file = truth_dir / f"{target}.yaml"
                if not truth_file.is_file():
                    raise SystemExit(f"no ground truth for {target}: {truth_file}")
                truths[target] = load_ground_truth(truth_file)
            for name, report in load_reports(label_dir):
                run = f"{folder.name}/{label_dir.name}/{Path(name).stem}"
                found, skipped = report_cases(target, run, report, truths[target])
                rows += found
                excluded += skipped
    return rows, excluded


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pick the default of verify.llm.abstain_below from bench runs"
    )
    parser.add_argument(
        "--results", type=Path, action="append", required=True, help="Bench run folder"
    )
    parser.add_argument("--truth-dir", type=Path, default=TRUTH_DIR)
    parser.add_argument("--out", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out = args.out or CALIBRATION_DIR / datetime.now(UTC).strftime(STAMP)
    existing = [name for name in OUTPUT_FILES if (out / name).exists()]
    if existing:
        raise SystemExit(f"refusing to overwrite {existing} in {out}")
    rows, excluded = collect_cases(args.results, args.truth_dir)
    models = sorted({row["model"] for row in rows if row["model"]})
    choice = choose_threshold(rows)
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdicts.json").write_text(
        json.dumps({"models": models, "rows": rows}, indent=2) + "\n"
    )
    abstain = {
        "models": models,
        **choice,
        "excluded": dict(excluded),
        "cases": len(rows),
    }
    (out / "abstain.json").write_text(json.dumps(abstain, indent=2) + "\n")
    sys.stdout.write(f"default {choice['default']} calibrated {choice['calibrated']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
