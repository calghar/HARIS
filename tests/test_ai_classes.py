import pytest

from haris.ai_security.findings import CLASS_PREFIX, ai_finding
from haris.ai_security.owasp_ai import load_mappings
from haris.core.confidence import _priors
from haris.core.vuln_class import get_registry

TOOLS = ("garak", "promptfoo")
KINDS = sorted(load_mappings().checks)


def emitted_classes() -> dict[str, str]:
    """Emitted vuln_class -> its confidence.yaml key."""
    classes = {
        ai_finding(kind, url="https://t.example/").vuln_class: f"ai_security.{kind}"
        for kind in KINDS
    }
    return classes | {CLASS_PREFIX + tool: tool for tool in TOOLS}


@pytest.mark.parametrize(("vuln_class", "prior_key"), emitted_classes().items())
def test_every_ai_class_is_registered_without_a_replay_oracle(vuln_class, prior_key):
    """Every emitted ai_* class is in vuln_classes.yaml and confidence.yaml."""
    registered = get_registry().classes[vuln_class]
    assert registered.oracle == "none"
    assert prior_key in _priors()[1]


@pytest.mark.parametrize("kind", KINDS)
def test_check_prior_equals_the_mapping_confidence(kind):
    assert (
        _priors()[1][f"ai_security.{kind}"] == load_mappings().checks[kind].confidence
    )
