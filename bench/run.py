import argparse
import logging
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict

BENCH_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = BENCH_DIR / "compose.yaml"
TRUTH_DIR = BENCH_DIR / "ground_truth"
RESULTS_DIR = BENCH_DIR / "results"
HEALTH_POLL_SECONDS = 3.0
DVWA_SETUP_PATH = "/setup.php"
PARTIAL_REPORT = "session.partial.json"

logger = logging.getLogger("bench")


class Target(BaseModel):
    model_config = ConfigDict(frozen=True)

    service: str
    container_port: int
    health_path: str
    scan_path: str = ""


TARGETS = {
    "juice_shop": Target(
        service="juice_shop",
        container_port=3000,
        health_path="/rest/admin/application-version",
    ),
    "dvwa": Target(service="dvwa", container_port=80, health_path="/login.php"),
    "webgoat": Target(
        service="webgoat",
        container_port=8080,
        health_path="/WebGoat/login",
        scan_path="/WebGoat",
    ),
    "spa_catchall": Target(
        service="spa_catchall", container_port=8080, health_path="/health"
    ),
    "vuln_ai_app": Target(
        service="vuln_ai_app", container_port=8080, health_path="/health"
    ),
}


def compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def resolve_base_url(target: Target) -> str:
    published = compose("port", target.service, str(target.container_port)).stdout
    host, _, port = published.strip().rpartition(":")
    return f"http://{host}:{port}"


def wait_healthy(base_url: str, health_path: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if httpx.get(base_url + health_path, timeout=5).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            raise TimeoutError(f"{base_url}{health_path} not healthy in {timeout}s")
        time.sleep(HEALTH_POLL_SECONDS)


def prepare_dvwa(base_url: str) -> None:
    """Create the DVWA database; its pages need it before any scan."""
    with httpx.Client(base_url=base_url, timeout=30, follow_redirects=True) as client:
        page = client.get(DVWA_SETUP_PATH).text
        token = re.search(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)", page)
        form = {"create_db": "Create / Reset Database"}
        if token:
            form["user_token"] = token.group(1)
        client.post(DVWA_SETUP_PATH, data=form).raise_for_status()


PREPARE = {"dvwa": prepare_dvwa}


def run_haris(
    haris_cmd: list[str], url: str, profile: str, out_dir: Path, report: Path
) -> None:
    """One scan; the JSON report is copied to `report` for the scorer."""
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    cmd = [
        *haris_cmd,
        "--url",
        url,
        "--profile",
        profile,
        "--output",
        str(out_dir),
        "--formats",
        "json",
        "--yes",
        "--allow-private",
    ]
    done = subprocess.run(cmd, capture_output=True, text=True, check=False)
    (out_dir / "stdout.log").write_text(done.stdout)
    (out_dir / "stderr.log").write_text(done.stderr)
    (out_dir / "wall_time_s.txt").write_text(f"{time.monotonic() - started:.3f}\n")
    reports = sorted(p for p in out_dir.glob("*.json") if p.name != PARTIAL_REPORT)
    if len(reports) != 1:
        raise RuntimeError(
            f"{out_dir}: expected one JSON report, found {len(reports)} "
            f"(haris exit code {done.returncode})"
        )
    report.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(reports[0], report)


def score(reports: Path, truth: Path, baseline: Path | None) -> None:
    cmd = [sys.executable, "-m", "haris.bench", "score", str(reports), str(truth)]
    if baseline:
        cmd += ["--baseline", str(baseline)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def bench_target(name: str, args: argparse.Namespace, results: Path) -> None:
    target = TARGETS[name]
    compose("up", "--detach", "--build", target.service)
    base_url = resolve_base_url(target)
    wait_healthy(base_url, target.health_path, args.health_timeout)
    if name in PREPARE:
        PREPARE[name](base_url)
    scan_url = base_url + target.scan_path
    profiles = {"runs": args.profile, "baseline": args.baseline_profile}
    for label, profile in profiles.items():
        if not profile:
            continue
        for run in range(1, args.runs + 1):
            run_haris(
                shlex.split(args.haris),
                scan_url,
                profile,
                results / name / "raw" / label / f"run{run}",
                results / name / label / f"run{run}.json",
            )
    baseline_dir = results / name / "baseline" if args.baseline_profile else None
    score(results / name / "runs", TRUTH_DIR / f"{name}.yaml", baseline_dir)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the HARIS benchmark")
    parser.add_argument("--targets", default=",".join(TARGETS), help="Comma list")
    parser.add_argument("--profile", required=True, help="HARIS profile to measure")
    parser.add_argument("--baseline-profile", help="Profile for FP-reduction baseline")
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
    results = args.results_dir / datetime.now(UTC).strftime("%Y-%m-%d")
    results.mkdir(parents=True, exist_ok=True)
    (results / "compose.resolved.yaml").write_text(compose("config").stdout)
    failures = 0
    try:
        for name in names:
            try:
                bench_target(name, args, results)
            except (RuntimeError, TimeoutError, subprocess.CalledProcessError) as exc:
                failures += 1
                logger.error(
                    "%s failed: %s %s", name, exc, getattr(exc, "stderr", "") or ""
                )
    finally:
        compose("down", "--volumes", "--remove-orphans")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
