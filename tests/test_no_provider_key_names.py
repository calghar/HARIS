"""No Python module under src/haris names a provider key variable."""

from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "haris"
FORBIDDEN = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_")


def test_no_provider_key_names_in_src() -> None:
    hits = [
        f"{path.relative_to(SRC.parent.parent)}:{number}: {name}"
        for path in sorted(SRC.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        for name in FORBIDDEN
        if name in line
    ]
    assert not hits, "provider key names in src/haris:\n" + "\n".join(hits)
