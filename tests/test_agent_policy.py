import argparse

import pytest

from haris.agent.policy import (
    activation_result,
    bind_cli,
    bind_policy,
    current_policy,
    policy_for_web,
    select_candidates,
)
from haris.agent.settings import load_agent_settings
from haris.cli import main
from haris.core.exit_codes import EXIT_USAGE
from haris.models import (
    CorrelatedFinding,
    Finding,
    Severity,
    Suppression,
    Verification,
    VerificationTier,
)

MATRIX = [
    ("--agent --i-have-authorization", "(absent)", "agent stage runs"),
    ("--agent", "(absent)", "exit 3"),
    ("--i-have-authorization", "(absent)", "agent stage skipped"),
    ("--agent --i-have-authorization", "HARIS_AGENT_DISABLED=1", "agent stage skipped"),
]


@pytest.mark.parametrize("flags,env,result", MATRIX)
def test_activation_matrix(flags: str, env: str, result: str):
    """Scenario: Activation matrix."""
    assert activation_result(flags, env) == result


def test_agent_without_authorisation_exits_before_a_scan(
    capsys: pytest.CaptureFixture[str],
):
    """Scenario: `--agent` without `--i-have-authorization` exits 3."""
    assert main(["--agent"]) == EXIT_USAGE
    assert "Scanning" not in capsys.readouterr().out


def test_bind_cli_skips_when_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HARIS_AGENT_DISABLED", "1")
    code = bind_cli(
        argparse.Namespace(
            agent=True,
            i_have_authorization=True,
            agent_allow_unsafe_methods=False,
            output=None,
        )
    )
    assert code is None
    assert current_policy() is None


def test_bind_cli_arms_an_authorised_run(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("HARIS_AGENT_DISABLED", raising=False)
    try:
        code = bind_cli(
            argparse.Namespace(
                agent=True,
                i_have_authorization=True,
                agent_allow_unsafe_methods=True,
                output="out",
            )
        )
        assert code is None
        policy = current_policy()
        assert policy is not None and policy.runs
        assert policy.allow_unsafe_methods is True
        assert policy.output_dir == "out"
    finally:
        bind_policy(None)


def test_web_hook_requires_admin_and_verified_target():
    assert (
        policy_for_web(is_admin=False, target_authorised=True, output_dir="o") is None
    )
    assert (
        policy_for_web(is_admin=True, target_authorised=False, output_dir="o") is None
    )
    policy = policy_for_web(is_admin=True, target_authorised=True, output_dir="o")
    assert policy is not None and policy.source == "web" and policy.runs


def test_packaged_agent_config_has_the_spec_defaults():
    settings = load_agent_settings()
    assert settings.max_tool_calls == 40
    assert settings.max_tokens == 300_000
    assert settings.wall_clock_s == 600
    assert settings.max_jobs == 10
    assert settings.max_requests == 300
    assert "xss_reflected" in settings.classes
    assert len(settings.classes) >= 6


def _case(
    *,
    severity: Severity = Severity.HIGH,
    tier: VerificationTier = VerificationTier.UNVERIFIED,
    vuln_class: str = "xss_reflected",
    suppressed: bool = False,
) -> CorrelatedFinding:
    finding = Finding(
        title="reflected",
        description="marker",
        severity=severity,
        url="http://127.0.0.1/search?q=1",
        parameter="q",
        vuln_class=vuln_class,
        verification=Verification(tier=tier),
        suppression=Suppression(reason="noise", author="a", expires="2099-01-01")
        if suppressed
        else None,
    )
    return CorrelatedFinding(canonical=finding, consensus_score=0.5)


def test_candidates_follow_tier_severity_and_class():
    settings = load_agent_settings()
    cases = [
        _case(),
        _case(tier=VerificationTier.REPLAY_VERIFIED),
        _case(tier=VerificationTier.EXPLOIT_VALIDATED),
        _case(tier=VerificationTier.REFUTED),
        _case(severity=Severity.LOW),
        _case(severity=Severity.INFO),
        _case(vuln_class="missing_header"),
        _case(suppressed=True),
    ]
    chosen = select_candidates(cases, settings)
    assert len(chosen) == 2
    assert all(c.canonical.vuln_class == "xss_reflected" for c in chosen)


def test_max_jobs_caps_the_candidate_list():
    settings = load_agent_settings().model_copy(update={"max_jobs": 1})
    chosen = select_candidates([_case(), _case()], settings)
    assert len(chosen) == 1


def test_verification_model_is_the_tier_gate():
    """Tier changes go through Verification.advance."""
    state = Verification()
    state.advance(VerificationTier.REPLAY_VERIFIED)
    state.advance(VerificationTier.EXPLOIT_VALIDATED)
    assert state.tier is VerificationTier.EXPLOIT_VALIDATED
