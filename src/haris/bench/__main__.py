import argparse
import sys
from pathlib import Path

from .render import render_markdown
from .score import load_reports, score_runs
from .truth import load_ground_truth

RESULT_STEM = "score"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m haris.bench")
    commands = parser.add_subparsers(dest="command", required=True)
    score = commands.add_parser(
        "score", help="Score HARIS JSON reports against ground truth"
    )
    score.add_argument(
        "report", type=Path, help="Report file, or directory of per-run reports"
    )
    score.add_argument("ground_truth", type=Path, help="Ground-truth YAML")
    score.add_argument(
        "--baseline", type=Path, help="Baseline report file or directory"
    )
    score.add_argument(
        "--out",
        type=Path,
        help="Output directory (default: <report dir>/score)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    truth = load_ground_truth(args.ground_truth)
    baseline = load_reports(args.baseline) if args.baseline else None
    result = score_runs(load_reports(args.report), truth, baseline)
    report_dir = args.report if args.report.is_dir() else args.report.parent
    out = args.out or report_dir / RESULT_STEM
    out.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(result)
    (out / f"{RESULT_STEM}.json").write_text(result.model_dump_json(indent=2) + "\n")
    (out / f"{RESULT_STEM}.md").write_text(markdown)
    sys.stdout.write(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
