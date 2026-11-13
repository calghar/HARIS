import argparse
import importlib.util
import logging
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx

BENCH_DIR = Path(__file__).resolve().parent
TRUTH_DIR = BENCH_DIR / "ground_truth"
RESULTS_DIR = BENCH_DIR / "results"
RESULTS_STAMP = "%Y-%m-%d-%H%M%S"
VERIFY_MODES = ("off", "replay", "llm")

logger = logging.getLogger("bench")


def load_sibling(name: str) -> ModuleType:
    """Import `bench/<name>.py` whether run as a script or loaded by path."""
    spec = importlib.util.spec_from_file_location(
        f"bench_{name}", Path(__file__).resolve().parent / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# `execute` reads `bench_callback` from `sys.modules`, so `callback` loads first.
callback = load_sibling("callback")
prepare = load_sibling("prepare")
execute = load_sibling("execute")

TARGETS = prepare.TARGETS
PREPARE = prepare.PREPARE
LOGIN = prepare.LOGIN
compose = prepare.compose
resolve_base_url = prepare.resolve_base_url
wait_healthy = prepare.wait_healthy
resolve_profile = execute.resolve_profile
run_haris = execute.run_haris
run_args = execute.run_args
score = execute.score

CALLBACK_TARGET = prepare.Target(
    service=callback.CALLBACK_SERVICE,
    container_port=callback.CALLBACK_CONTAINER_PORT,
    health_path=callback.CALLBACK_HEALTH_PATH,
)


def scan_target(name: str, args: argparse.Namespace, results: Path) -> None:
    target = TARGETS[name]
    compose("up", "--detach", "--build", target.service)
    base_url = resolve_base_url(target)
    wait_healthy(base_url, target.health_path, args.health_timeout)
    compose("up", "--detach", "--build", CALLBACK_TARGET.service)
    callback_url = resolve_base_url(CALLBACK_TARGET)
    wait_healthy(callback_url, CALLBACK_TARGET.health_path, args.health_timeout)
    execute.WAPITI_ENDPOINTS.update(callback.wapiti_endpoints(callback_url))
    execute.TARGET_EXCLUDED_PATHS[:] = target.excluded_paths
    execute.TARGET_SCANNER_ARGS.clear()
    execute.TARGET_SCANNER_ARGS.update(target.scanner_extra_args)
    scan_url = base_url + target.scan_path
    profiles = {
        "runs": resolve_profile(target, args.profile),
        "baseline": args.baseline_profile,
    }
    for label, profile in profiles.items():
        if not profile:
            continue
        for run in range(1, args.runs + 1):
            # A scan changes target state, so every run starts from a reset.
            if name in PREPARE:
                PREPARE[name](base_url)
            session_cookie = LOGIN[name](base_url) if name in LOGIN else None
            run_haris(
                shlex.split(args.haris),
                scan_url,
                profile,
                results / name / "raw" / label / f"run{run}",
                results / name / label / f"run{run}.json",
                run_args(target, args.verify) if label == "runs" else (),
                session_cookie,
            )
    baseline_dir = results / name / "baseline" if args.baseline_profile else None
    score(results / name / "runs", TRUTH_DIR / f"{name}.yaml", baseline_dir)


def bench_target(name: str, args: argparse.Namespace, results: Path) -> None:
    """Scan one target, then remove it so the next one has the VM's memory."""
    target = TARGETS[name]
    try:
        scan_target(name, args, results)
    finally:
        compose(
            "rm", "--stop", "--force", "--volumes", target.service, *target.companions
        )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the HARIS benchmark")
    parser.add_argument("--targets", default=",".join(TARGETS), help="Comma list")
    parser.add_argument(
        "--profile",
        help="HARIS profile for every target (default: each target's own profile)",
    )
    parser.add_argument("--baseline-profile", help="Profile for FP-reduction baseline")
    parser.add_argument(
        "--verify", choices=VERIFY_MODES, help="haris --verify mode for the runs"
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--haris", default="haris", help="HARIS command line")
    parser.add_argument("--health-timeout", type=float, default=300.0)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    args = parse_args(argv)
    names = args.targets.split(",")
    unknown = [name for name in names if name not in TARGETS]
    if unknown:
        raise SystemExit(f"unknown targets: {unknown}")
    results = args.results_dir / datetime.now(UTC).strftime(RESULTS_STAMP)
    results.mkdir(parents=True)
    (results / "compose.resolved.yaml").write_text(compose("config").stdout)
    failures = 0
    try:
        for name in names:
            try:
                bench_target(name, args, results)
            except (
                RuntimeError,
                TimeoutError,
                subprocess.CalledProcessError,
                httpx.HTTPError,
            ) as exc:
                failures += 1
                logger.error(
                    "%s failed: %s %s", name, exc, getattr(exc, "stderr", "") or ""
                )
    finally:
        compose("down", "--volumes", "--remove-orphans")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
