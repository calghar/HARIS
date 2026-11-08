import json
import re
from pathlib import Path

CONFIG_DIR_LINE = re.compile(r"Nuclei Config Directory:\s*(.+?)\s*$")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
TEMPLATES_CONFIG_FILE = ".templates-config.json"
TEMPLATES_DIR_KEY = "nuclei-templates-directory"


def config_dir_from(version_output: str) -> Path | None:
    """Read nuclei's config directory from ``nuclei -version`` output."""
    for line in ANSI_ESCAPE.sub("", version_output).splitlines():
        match = CONFIG_DIR_LINE.search(line)
        if match:
            return Path(match.group(1))
    return None


def templates_dir_from(config_json: str) -> Path | None:
    """Read the template root from nuclei's ``.templates-config.json``."""
    try:
        value = json.loads(config_json).get(TEMPLATES_DIR_KEY)
    except (json.JSONDecodeError, AttributeError):
        return None
    return Path(value) if isinstance(value, str) and value else None
