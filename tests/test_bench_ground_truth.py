from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from haris.bench.truth import GroundTruth, load_ground_truth

BENCH = Path(__file__).resolve().parent.parent / "bench"
TRUTH_FILES = sorted((BENCH / "ground_truth").glob("*.yaml"))
EXPECTED_TARGETS = {"juice_shop", "dvwa", "webgoat", "spa_catchall", "vuln_ai_app"}
ENTRY = {
    "id": "e",
    "method": "GET",
    "url": "/x",
    "vuln_class": "sqli_error",
    "cwe": "CWE-89",
    "expected": "true_positive",
}


def test_every_target_has_ground_truth() -> None:
    assert {path.stem for path in TRUTH_FILES} == EXPECTED_TARGETS


@pytest.mark.parametrize("path", TRUTH_FILES, ids=lambda p: p.stem)
def test_ground_truth_loads_and_names_its_target(path: Path) -> None:
    truth = load_ground_truth(path)
    assert truth.target == path.stem


@pytest.mark.parametrize("path", TRUTH_FILES, ids=lambda p: p.stem)
def test_external_entries_cite_a_source_url(path: Path) -> None:
    truth = load_ground_truth(path)
    if truth.kind == "external":
        assert truth.entries
        assert all(str(entry.source).startswith("https://") for entry in truth.entries)


def test_spa_catchall_truth_is_empty_and_ai_app_truth_is_not() -> None:
    assert load_ground_truth(BENCH / "ground_truth" / "spa_catchall.yaml").entries == []
    assert load_ground_truth(BENCH / "ground_truth" / "vuln_ai_app.yaml").entries


def test_external_entry_without_source_is_rejected() -> None:
    with pytest.raises(ValidationError, match="without source"):
        GroundTruth.model_validate(
            {"target": "t", "kind": "external", "entries": [ENTRY]}
        )


def test_duplicate_entry_ids_are_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate entry ids"):
        GroundTruth.model_validate(
            {"target": "t", "kind": "fixture", "entries": [ENTRY, ENTRY]}
        )


@pytest.mark.parametrize(
    "patch",
    [{"cwe": "89"}, {"expected": "false_positive"}, {"unknown": 1}],
    ids=["bad-cwe", "bad-expected", "unknown-field"],
)
def test_invalid_entry_is_rejected(patch: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        GroundTruth.model_validate(
            {"target": "t", "kind": "fixture", "entries": [ENTRY | patch]}
        )


def test_compose_binds_every_port_to_loopback() -> None:
    compose = yaml.safe_load((BENCH / "compose.yaml").read_text())
    ports = [
        port
        for service in compose["services"].values()
        for port in service.get("ports", [])
    ]
    assert ports
    assert all(str(port).startswith("127.0.0.1:") for port in ports)
    images = [s["image"] for s in compose["services"].values() if "image" in s]
    assert all("@sha256:" in image for image in images)
