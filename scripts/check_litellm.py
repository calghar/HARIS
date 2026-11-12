import re
import sys
import tomllib
from pathlib import Path

DENIED_VERSIONS = frozenset({"1.82.7", "1.82.8", "1.107.0"})
EXTRA = "llm"
EXACT_PIN = re.compile(r"^litellm==[^=<>!~,\s]+$")


def _is_litellm(requirement: object) -> bool:
    if not isinstance(requirement, str):
        return False
    return re.split(r"[\s\[=<>!~;,]", requirement.strip(), maxsplit=1)[0] == "litellm"


def check_manifest(pyproject: dict) -> list[str]:
    errors = []
    project = pyproject.get("project", {})
    if any(_is_litellm(item) for item in project.get("dependencies", [])):
        errors.append("litellm is in the main dependencies")
    extras = project.get("optional-dependencies", {})
    for name, items in {**extras, **pyproject.get("dependency-groups", {})}.items():
        if name != EXTRA and any(_is_litellm(item) for item in items):
            errors.append(f"litellm is in {name!r}, not only in the {EXTRA!r} extra")
    pins = [item for item in extras.get(EXTRA, []) if _is_litellm(item)]
    if len(pins) != 1 or not EXACT_PIN.match(pins[0]):
        errors.append(f"the {EXTRA!r} extra needs one exact 'litellm==X' entry")
    return errors


def check_lock(lock: dict) -> list[str]:
    packages = [p for p in lock.get("package", []) if p.get("name") == "litellm"]
    if not packages:
        return ["uv.lock has no litellm entry"]
    errors = []
    for package in packages:
        version = package.get("version", "")
        if version in DENIED_VERSIONS:
            errors.append(f"uv.lock resolves denied litellm {version}")
        files = list(package.get("wheels", []))
        if "sdist" in package:
            files.append(package["sdist"])
        if not files or any(not f.get("hash", "").startswith("sha256:") for f in files):
            errors.append(f"uv.lock has a litellm {version} file without a hash")
    return errors


def main(root: Path) -> int:
    with (root / "pyproject.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    with (root / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    errors = check_manifest(manifest) + check_lock(lock)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(Path(__file__).resolve().parents[1]))
