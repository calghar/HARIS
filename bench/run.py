import argparse
import importlib.util
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx
import yaml
from pydantic import BaseModel, ConfigDict

from haris.config.loader import default_config_path

BENCH_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = BENCH_DIR / "compose.yaml"
TRUTH_DIR = BENCH_DIR / "ground_truth"
RESULTS_DIR = BENCH_DIR / "results"
RESULTS_STAMP = "%Y-%m-%d-%H%M%S"
HEALTH_POLL_SECONDS = 3.0
DEFAULT_PROFILE = "quick"
DVWA_SETUP_PATH = "/setup.php"
DVWA_LOGOUT_PATH = "/logout.php"
DVWA_HOME_PATH = "index.php"
DVWA_PREPARE_TIMEOUT_SECONDS = 120.0
DVWA_LOGIN_PATH = "/login.php"
DVWA_SECURITY_PATH = "/security.php"
DVWA_USER = "admin"
DVWA_PASSWORD = "password"
DVWA_SECURITY_LEVEL = "low"
DVWA_TOKEN = re.compile(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)")
WEBGOAT_REGISTER_PATH = "/WebGoat/register.mvc"
WEBGOAT_LOGIN_PATH = "/WebGoat/login"
WEBGOAT_HOME_PATH = "/WebGoat/welcome.mvc"
WEBGOAT_USER = "haris-bench"
WEBGOAT_PASSWORD = "harisbench"
LOGIN_TIMEOUT_SECONDS = 30
COOKIE_HEADER = "Cookie"
AUTH_HEADER_ENV = "HARIS_AUTH_HEADER"
REDACTED = "<redacted>"
PARTIAL_REPORT = "session.partial.json"

logger = logging.getLogger("bench")


def load_sibling(name: str) -> ModuleType:
    """Import `bench/<name>.py` whether run as a script or loaded by path."""
    spec = importlib.util.spec_from_file_location(
        f"bench_{name}", Path(__file__).resolve().parent / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


callback = load_sibling("callback")
# Wapiti options of the running callback service; set per target in scan_target.
WAPITI_ENDPOINTS: dict[str, str] = {}
# Excluded paths of the running target; set per target in scan_target.
TARGET_EXCLUDED_PATHS: list[str] = []


class Target(BaseModel):
    model_config = ConfigDict(frozen=True)

    service: str
    container_port: int
    health_path: str
    scan_path: str = ""
    profile: str | None = None
    haris_args: tuple[str, ...] = ()
    companions: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()


TARGETS = {
    "juice_shop": Target(
        service="juice_shop",
        container_port=3000,
        health_path="/rest/admin/application-version",
    ),
    "dvwa": Target(
        service="dvwa",
        container_port=80,
        health_path="/login.php",
        companions=("dvwa_db",),
        excluded_paths=(DVWA_LOGOUT_PATH, DVWA_SETUP_PATH),
    ),
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
        service="vuln_ai_app",
        container_port=8080,
        health_path="/health",
        profile="ai-security",
        haris_args=("--ai-active", "--i-have-authorization"),
    ),
}
CALLBACK_TARGET = Target(
    service=callback.CALLBACK_SERVICE,
    container_port=callback.CALLBACK_CONTAINER_PORT,
    health_path=callback.CALLBACK_HEALTH_PATH,
)


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


def dvwa_form(client: httpx.Client, path: str, **fields: str) -> dict[str, str]:
    """`fields` plus the `user_token` CSRF value found on the page at `path`."""
    token = DVWA_TOKEN.search(client.get(path).text)
    return {**fields, "user_token": token.group(1)} if token else dict(fields)


def prepare_dvwa(
    base_url: str,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DVWA_PREPARE_TIMEOUT_SECONDS,
) -> None:
    """Create the DVWA database, retrying until MariaDB accepts it."""
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=base_url, timeout=30, transport=transport) as client:
        while True:
            form = dvwa_form(
                client, DVWA_SETUP_PATH, create_db="Create / Reset Database"
            )
            client.post(
                DVWA_SETUP_PATH, data=form, follow_redirects=True
            ).raise_for_status()
            probe = dvwa_form(
                client,
                DVWA_LOGIN_PATH,
                username=DVWA_USER,
                password=DVWA_PASSWORD,
                Login="Login",
            )
            login = client.post(DVWA_LOGIN_PATH, data=probe)
            if login.headers.get("location", "").endswith(DVWA_HOME_PATH):
                return
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"{base_url}: DVWA database was not created in {timeout}s"
                )
            time.sleep(HEALTH_POLL_SECONDS)


PREPARE = {"dvwa": prepare_dvwa}


def cookie_header(client: httpx.Client) -> str:
    """The client's cookies as one `Cookie` header value."""
    cookies = {cookie.name: cookie.value for cookie in client.cookies.jar}
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def login_dvwa(base_url: str, transport: httpx.BaseTransport | None = None) -> str:
    """Log in as the default admin, set the security level; returns the cookies."""
    with httpx.Client(
        base_url=base_url,
        timeout=LOGIN_TIMEOUT_SECONDS,
        follow_redirects=True,
        transport=transport,
    ) as client:
        form = dvwa_form(
            client,
            DVWA_LOGIN_PATH,
            username=DVWA_USER,
            password=DVWA_PASSWORD,
            Login="Login",
        )
        done = client.post(DVWA_LOGIN_PATH, data=form)
        done.raise_for_status()
        if done.url.path == DVWA_LOGIN_PATH:
            raise RuntimeError(f"{base_url}: DVWA login was rejected")
        form = dvwa_form(
            client,
            DVWA_SECURITY_PATH,
            security=DVWA_SECURITY_LEVEL,
            seclev_submit="Submit",
        )
        client.post(DVWA_SECURITY_PATH, data=form).raise_for_status()
        return cookie_header(client)


def login_webgoat(base_url: str, transport: httpx.BaseTransport | None = None) -> str:
    """Register the bench user (a repeat is harmless), log in; returns the cookies."""
    credentials = {"username": WEBGOAT_USER, "password": WEBGOAT_PASSWORD}
    with httpx.Client(
        base_url=base_url,
        timeout=LOGIN_TIMEOUT_SECONDS,
        follow_redirects=True,
        transport=transport,
    ) as client:
        client.post(
            WEBGOAT_REGISTER_PATH,
            data={
                **credentials,
                "matchingPassword": WEBGOAT_PASSWORD,
                "agree": "agree",
            },
        )
        client.post(WEBGOAT_LOGIN_PATH, data=credentials).raise_for_status()
        home = client.get(WEBGOAT_HOME_PATH)
        if home.status_code != httpx.codes.OK or home.url.path == WEBGOAT_LOGIN_PATH:
            raise RuntimeError(f"{base_url}: WebGoat login was rejected")
        return cookie_header(client)


LOGIN = {"dvwa": login_dvwa, "webgoat": login_webgoat}


def resolve_profile(target: Target, override: str | None) -> str:
    """`--profile` wins over the target's own profile, which wins over the default."""
    return override or target.profile or DEFAULT_PROFILE


def run_command(
    cmd: list[str], session_cookie: str | None
) -> subprocess.CompletedProcess[str]:
    """Run `cmd`; a session cookie travels in the environment, never in argv."""
    if session_cookie is None and not (WAPITI_ENDPOINTS or TARGET_EXCLUDED_PATHS):
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


def scan_target(name: str, args: argparse.Namespace, results: Path) -> None:
    target = TARGETS[name]
    compose("up", "--detach", "--build", target.service)
    base_url = resolve_base_url(target)
    wait_healthy(base_url, target.health_path, args.health_timeout)
    compose("up", "--detach", "--build", CALLBACK_TARGET.service)
    callback_url = resolve_base_url(CALLBACK_TARGET)
    wait_healthy(callback_url, CALLBACK_TARGET.health_path, args.health_timeout)
    WAPITI_ENDPOINTS.update(callback.wapiti_endpoints(callback_url))
    TARGET_EXCLUDED_PATHS[:] = target.excluded_paths
    if name in PREPARE:
        PREPARE[name](base_url)
    scan_url = base_url + target.scan_path
    profiles = {
        "runs": resolve_profile(target, args.profile),
        "baseline": args.baseline_profile,
    }
    for label, profile in profiles.items():
        if not profile:
            continue
        for run in range(1, args.runs + 1):
            session_cookie = LOGIN[name](base_url) if name in LOGIN else None
            run_haris(
                shlex.split(args.haris),
                scan_url,
                profile,
                results / name / "raw" / label / f"run{run}",
                results / name / label / f"run{run}.json",
                target.haris_args if label == "runs" else (),
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
