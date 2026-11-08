from .score import METRICS, BenchScore, Stat


def _cell(stat: Stat | None) -> str:
    if stat is None:
        return "n/a"
    return f"{stat.mean:.3f} ± {stat.stddev:.3f} (n={stat.n})"


def render_markdown(score: BenchScore) -> str:
    lines = [
        f"# Benchmark score: {score.target}",
        "",
        f"Runs: {len(score.runs)}. Baseline runs: {score.baseline_runs}. "
        "Values are mean ± sample stddev.",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    lines += [f"| {metric} | {_cell(score.summary[metric])} |" for metric in METRICS]
    lines += [
        "",
        "| Run | Findings | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {run.source} | {run.findings} | {run.true_positives} "
        f"| {run.false_positives} | {run.false_negatives} | {run.precision:.3f} "
        f"| {run.recall:.3f} | {run.f1:.3f} |"
        for run in score.runs
    ]
    return "\n".join(lines) + "\n"
