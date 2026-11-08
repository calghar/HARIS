from importlib.resources import files
from pathlib import Path

CWD_CONFIG_DIR = Path("config")


def packaged_config_dir() -> Path:
    return Path(str(files("haris.resources") / "config"))


def resolve_config_file(relative: str) -> Path:
    """Return ``./config/<relative>`` if present, else the packaged file."""
    override = CWD_CONFIG_DIR / relative
    return override if override.is_file() else packaged_config_dir() / relative
