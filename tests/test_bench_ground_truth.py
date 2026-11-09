from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from haris.bench.truth import GroundTruth, load_ground_truth
from haris.core.vuln_class import get_registry

BENCH = Path(__file__).resolve().parent.parent / "bench"
TRUTH_FILES = sorted((BENCH / "ground_truth").glob("*.yaml"))
FIXTURE_TARGETS = {"spa_catchall", "vuln_ai_app"}
EXPECTED_TARGETS = {"juice_shop", "dvwa", "webgoat"} | FIXTURE_TARGETS
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


def test_spa_catchall_truth_has_no_path_or_debug_class() -> None:
    truth = load_ground_truth(BENCH / "ground_truth" / "spa_catchall.yaml")
    registry = get_registry().classes
    assert truth.entries
    assert not truth.ignore
    assert {registry[entry.vuln_class].granularity for entry in truth.entries} == {
        "host"
    }


@pytest.mark.parametrize(
    "path", [p for p in TRUTH_FILES if p.stem in FIXTURE_TARGETS], ids=lambda p: p.stem
)
def test_fixture_truth_classes_exist_with_their_primary_cwe(path: Path) -> None:
    truth = load_ground_truth(path)
    registry = get_registry().classes
    classes = [entry.vuln_class for entry in truth.entries]
    classes += [entry.vuln_class for entry in truth.ignore]
    assert set(classes) <= registry.keys()
    assert all(
        registry[entry.vuln_class].primary_cwe == entry.cwe for entry in truth.entries
    )


@pytest.mark.parametrize("path", TRUTH_FILES, ids=lambda p: p.stem)
def test_truth_class_ids_are_emitted_by_haris(path: Path) -> None:
    truth = load_ground_truth(path)
    tokens = [entry.vuln_class for entry in truth.entries]
    tokens += [entry.vuln_class for entry in truth.ignore]
    unknown = [
        t
        for t in tokens
        if not t.startswith("unclassified:") and t not in get_registry().classes
    ]
    assert not unknown, f"{path.name}: not in vuln_classes.yaml: {unknown}"


def test_ignore_entry_loads_with_optional_parameter() -> None:
    truth = GroundTruth.model_validate(
        {
            "target": "t",
            "kind": "fixture",
            "entries": [],
            "ignore": [
                {"vuln_class": "sensitive_file", "url": "/health", "reason": "r"},
                {
                    "vuln_class": "x",
                    "url": "/a",
                    "parameter": "p",
                    "reason": "r",
                },
            ],
        }
    )
    assert [entry.parameter for entry in truth.ignore] == [None, "p"]


@pytest.mark.parametrize("reason", [None, ""], ids=["missing", "empty"])
def test_ignore_entry_without_reason_is_rejected(reason: str | None) -> None:
    entry: dict[str, object] = {"vuln_class": "sensitive_file", "url": "/health"}
    if reason is not None:
        entry["reason"] = reason
    with pytest.raises(ValidationError, match="reason"):
        GroundTruth.model_validate(
            {"target": "t", "kind": "fixture", "entries": [], "ignore": [entry]}
        )


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
