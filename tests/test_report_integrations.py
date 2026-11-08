import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / "action.yml", ROOT / "integrations/gitlab/templates/haris.yml"]
SHA_PIN = re.compile(r"@[0-9a-f]{40}(\s|$)")


def test_integration_files_parse():
    for path in FILES:
        assert all(yaml.safe_load_all(path.read_text(encoding="utf-8")))


def test_every_action_is_pinned_by_commit_sha():
    uses = [
        line.split("uses:", 1)[1].strip()
        for line in FILES[0].read_text(encoding="utf-8").splitlines()
        if "uses:" in line
    ]
    assert uses
    assert all(SHA_PIN.search(u) for u in uses), uses
