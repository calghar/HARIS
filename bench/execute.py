import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from haris.config.loader import default_config_path

if TYPE_CHECKING:
    from prepare import Target

DEFAULT_PROFILE = "quick"
COOKIE_HEADER = "Cookie"
AUTH_HEADER_ENV = "HARIS_AUTH_HEADER"
REDACTED = "<redacted>"
PARTIAL_REPORT = "session.partial.json"

# `run.py` loads `callback` first, as `bench_callback`.
callback = sys.modules["bench_callback"]
# Wapiti options of the running callback service; set per target in scan_target.
WAPITI_ENDPOINTS: dict[str, str] = {}
# Excluded paths of the running target; set per target in scan_target.
TARGET_EXCLUDED_PATHS: list[str] = []
# Per-scanner extra args of the running target; set per target in scan_target.
TARGET_SCANNER_ARGS: dict[str, tuple[str, ...]] = {}


def resolve_profile(target: "Target", override: str | None) -> str:
    """`--profile` wins over the target's own profile, which wins over the default."""
    return override or target.profile or DEFAULT_PROFILE


def run_command(
    cmd: list[str], session_cookie: str | None
) -> subprocess.CompletedProcess[str]:
    """Run `cmd`; a session cookie travels in the environment, never in argv."""
    tuned = WAPITI_ENDPOINTS or TARGET_EXCLUDED_PATHS or TARGET_SCANNER_ARGS
    if session_cookie is None and not tuned:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "auth.yaml"
        raw = yaml.safe_load(default_config_path().read_text()) or {}
        if session_cookie is not None:
            raw.setdefault("target", {})["auth"] = {
                "method": "header",
                "header_name": COOKIE_HEADER,
            }
        callback.apply_wapiti_endpoints(raw, WAPITI_ENDPOINTS)
        callback.apply_scanner_extra_args(raw, TARGET_SCANNER_ARGS)
        scope = raw.setdefault("target", {}).setdefault("scope", {})
        scope["excluded_paths"] = list(
            dict.fromkeys([*scope.get("excluded_paths", []), *TARGET_EXCLUDED_PATHS])
        )
        config.write_text(yaml.safe_dump(raw))
        return subprocess.run(
            [*cmd, "--config", str(config)],
            capture_output=True,
            text=True,
            check=False,
            env=(
                {**os.environ, AUTH_HEADER_ENV: session_cookie}
                if session_cookie is not None
                else None
            ),
        )


def run_haris(
    haris_cmd: list[str],
    url: str,
    profile: str,
    out_dir: Path,
    report: Path,
    extra_args: tuple[str, ...] = (),
    session_cookie: str | None = None,
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
        *extra_args,
    ]
    done = run_command(cmd, session_cookie)
    streams = {"stdout.log": done.stdout, "stderr.log": done.stderr}
    for name, text in streams.items():
        (out_dir / name).write_text(
            text.replace(session_cookie, REDACTED) if session_cookie else text
        )
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


def run_args(target: "Target", verify: str | None) -> tuple[str, ...]:
    return (*target.haris_args, *(("--verify", verify) if verify else ()))
