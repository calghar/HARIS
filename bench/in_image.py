import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

IMAGE = os.environ.get("HARIS_BENCH_IMAGE", "haris-prod:bench")
HOST_ALIAS = "host.containers.internal"
LOOPBACK = ("127.0.0.1", "localhost")
REPORT_DIR = "/app/reports/out"
CONFIG_PATH = "/tmp/bench-config.yaml"  # nosec B108: path inside the container
HOME_VOLUME = "haris-bench-home"
FORWARDED_ENV = ("HARIS_AUTH_HEADER", "LITELLM_API_KEY")


def to_container_host(text: str) -> str:
    for loopback in LOOPBACK:
        text = text.replace(loopback, HOST_ALIAS)
    return text


def container_args(argv: list[str]) -> tuple[list[str], Path | None, Path | None]:
    """Argv for `haris` in the container, plus the host output and config paths."""
    args = [to_container_host(arg) for arg in argv]
    paths: dict[str, Path | None] = {"--output": None, "--config": None}
    container_paths = {"--output": REPORT_DIR, "--config": CONFIG_PATH}
    for flag in paths:
        if flag in args:
            at = args.index(flag) + 1
            paths[flag] = Path(argv[at])
            args[at] = container_paths[flag]
    return args, paths["--output"], paths["--config"]


def docker(*args: str) -> int:
    return subprocess.run(["docker", *args], check=False).returncode


def main(argv: list[str]) -> int:
    args, output, config = container_args(argv)
    name = f"haris-bench-run-{uuid.uuid4().hex[:8]}"
    env = [part for var in FORWARDED_ENV if var in os.environ for part in ("-e", var)]
    created = docker(
        "create", "--name", name, "--add-host", f"{HOST_ALIAS}:host-gateway",
        "-v", f"{HOME_VOLUME}:/home/haris", *env, IMAGE, "haris", *args,
    )  # fmt: skip
    if created:
        return created
    try:
        if config:
            with tempfile.TemporaryDirectory() as tmp:
                copy = Path(tmp) / "config.yaml"
                copy.write_text(to_container_host(config.read_text()))
                docker("cp", str(copy), f"{name}:{CONFIG_PATH}")
        status = docker("start", "--attach", name)
        if output:
            output.mkdir(parents=True, exist_ok=True)
            docker("cp", f"{name}:{REPORT_DIR}/.", str(output))
        return status
    finally:
        docker("rm", "--force", name)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
