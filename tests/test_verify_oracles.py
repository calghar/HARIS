import re
from urllib.parse import urlsplit

import pytest

from haris.core.vuln_class import get_registry
from haris.models import (
    CorrelatedFinding,
    Scope,
    Suppression,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from haris.verify.oracles import ORACLES
from haris.verify.probe import Prober
from haris.verify.replay import CAP_REASON, ReplayReport, replay
from haris.verify.settings import load_verify_settings
from haris.verify.timing import timing_positive
from tests.verify_server import case, fast_settings, make_client, serve

XSS = "Cross Site Scripting"
HEADER = "Missing X-Frame-Options header"
T = VerificationTier


def run(
    url: str,
    *cases: CorrelatedFinding,
    scope: Scope | None = None,
    **settings: object,
) -> tuple[ReplayReport, list[str]]:
    with make_client(url, scope) as client:
        report = replay(list(cases), client, fast_settings(**settings))
        return report, [e.url for e in client.log.entries()]


@pytest.mark.parametrize(
    ("path", "tier"),
    [
        ("/search", T.REPLAY_VERIFIED),
        ("/encoded", T.UNVERIFIED),
        ("/json", T.UNVERIFIED),
        ("/script", T.UNVERIFIED),
    ],
    ids=["raw-html", "html-encoded", "json", "inside-script-literal"],
)
def test_reflection_oracle(path, tier):
    """Scenario: Oracle matrix (xss_reflected / reflection)."""
    with serve() as fx:
        xss = case(XSS, f"{fx.url}{path}?q=x")
        run(fx.url, xss)
    verification = xss.canonical.verification
    assert verification.tier == tier
    assert verification.method == VerificationMethod.REPLAY
    assert verification.oracle == VerificationOracle.REFLECTION


@pytest.mark.parametrize(
    ("path", "tier"),
    [("/sqli", T.REPLAY_VERIFIED), ("/always", T.UNVERIFIED)],
    ids=["probe-only", "probe-and-control"],
)
def test_error_signature_oracle(path, tier):
    """Scenario: Oracle matrix (sqli_error / error_signature)."""
    with serve() as fx:
        sqli = case("SQL Injection", f"{fx.url}{path}?id=1", parameter="id")
        run(fx.url, sqli)
    assert sqli.canonical.verification.tier == tier


@pytest.mark.parametrize(
    ("path", "tier"),
    [("/sleep", T.REPLAY_VERIFIED), ("/slow", T.UNVERIFIED)],
    ids=["sleeps-on-payload", "slow-but-constant"],
)
def test_timing_oracle_on_a_real_server(path, tier):
    """Scenario: Oracle matrix (sqli_time / timing)."""
    with serve() as fx:
        blind = case("Blind SQL Injection", f"{fx.url}{path}?id=1", parameter="id")
        run(fx.url, blind)
    assert blind.canonical.verification.tier == tier


@pytest.mark.parametrize(
    ("probe", "control", "expected"),
    [
        ([5.4, 5.2, 5.3], [0.2, 0.3, 0.2], True),
        ([3.1, 0.2, 5.5], [0.2, 0.3, 0.2], False),
        ([5.1, 5.2, 5.0], [5.0, 5.1, 5.0], False),
    ],
)
def test_timing_decision_with_five_second_delay(probe, control, expected):
    """Scenario: Oracle matrix (timing rows with D=5)."""
    assert timing_positive(probe, control, 5.0, 0.8) is expected


@pytest.mark.parametrize(
    ("path", "tier", "score"),
    [
        ("/nohdr", T.REPLAY_VERIFIED, 0.9),
        ("/badhsts", T.REPLAY_VERIFIED, 0.9),
        ("/hdr", T.REFUTED, 0.0),
        ("/flaky", T.UNVERIFIED, None),
    ],
    ids=["absent", "invalid-value", "present-and-valid", "present-in-one-get"],
)
def test_header_presence_oracle(path, tier, score):
    """Scenario: Oracle matrix (missing_header / header_presence)."""
    name = "Strict-Transport-Security" if path == "/badhsts" else "X-Frame-Options"
    with serve() as fx:
        missing = case(
            f"Missing {name} header",
            f"{fx.url}{path}",
            scanner="header_checks",
            parameter=name,
        )
        before = missing.canonical.confidence_score
        run(fx.url, missing)
    assert missing.canonical.verification.tier == tier
    assert missing.canonical.confidence_score == (
        before if score is None else pytest.approx(score, abs=0.1)
    )
    assert missing.canonical.verification.oracle == VerificationOracle.HEADER_PRESENCE


def test_header_name_comes_from_the_title_when_parameter_is_empty():
    with serve() as fx:
        missing = case(HEADER, f"{fx.url}/hdr", scanner="header_checks", parameter="")
        run(fx.url, missing)
    assert missing.canonical.verification.tier == T.REFUTED


@pytest.mark.parametrize(
    ("path", "outcome"), [("/chat", "positive"), ("/echo", "inconclusive")]
)
def test_canary_oracle(path, outcome):
    with serve() as fx:
        finding = case("Prompt injection", f"{fx.url}{path}", parameter="msg")
        with make_client(fx.url) as client:
            prober = Prober(client, 50)
            result = ORACLES["canary"].run(finding.canonical, prober, fast_settings())
    assert result.outcome == outcome


def test_post_finding_is_replayed_as_post_only_when_scope_allows_it():
    """Scenario: Oracle matrix; POST only when the finding originated from POST."""
    scope = Scope(rate_limit_rps=1000.0, allowed_methods=["GET", "POST"])
    with serve() as fx:
        post = case(XSS, f"{fx.url}/form", method="POST")
        get = case(XSS, f"{fx.url}/search?q=1")
        run(fx.url, post, get, scope=scope)
    assert post.canonical.verification.tier == T.REPLAY_VERIFIED
    assert [m for m, p in fx.seen if p.startswith("/form")] == ["POST", "POST"]
    assert {m for m, p in fx.seen if p.startswith("/search")} == {"GET"}


def test_method_outside_scope_is_not_replayed():
    """Scenario: Method outside scope is not replayed."""
    with serve() as fx:
        post = case(XSS, f"{fx.url}/form", method="POST")
        report, _ = run(fx.url, post)
    assert fx.seen == []
    assert post.canonical.verification.method == VerificationMethod.NONE
    assert report.requests == 0


def test_replay_budget_exhausted_stops_with_a_recorded_reason():
    """Scenario: Replay budget exhausted."""
    with serve() as fx:
        cases = [case(XSS, f"{fx.url}/search?q=1") for i in range(3)]
        report, _ = run(fx.url, *cases, max_requests=4)
    assert len(fx.seen) == 4
    assert [c.canonical.verification.tier for c in cases] == [
        T.REPLAY_VERIFIED,
        T.REPLAY_VERIFIED,
        T.UNVERIFIED,
    ]
    third = cases[2].canonical
    assert third.verification.method == VerificationMethod.NONE
    assert report.skipped == {third.finding_id: CAP_REASON}
    assert report.requests == 4


def test_scope_request_cap_stops_replay_and_leaves_the_rest_unverified():
    scope = Scope(rate_limit_rps=1000.0, max_requests=3)
    with serve() as fx:
        cases = [case(XSS, f"{fx.url}/search?q=1") for i in range(2)]
        report, _ = run(fx.url, *cases, scope=scope)
    assert len(fx.seen) == 3
    assert cases[0].canonical.verification.tier == T.REPLAY_VERIFIED
    assert cases[1].canonical.verification.tier == T.UNVERIFIED
    assert cases[1].canonical.verification.method == VerificationMethod.NONE
    assert "max_requests" in report.skipped[cases[1].canonical.finding_id]


def test_out_of_scope_redirect_hop_is_not_followed():
    with serve() as fx:
        xss = case(XSS, f"{fx.url}/redirect?q=1")
        _, urls = run(fx.url, xss)
    assert {urlsplit(u).hostname for u in urls} == {"127.0.0.1"}
    assert len(fx.seen) == 2
    assert xss.canonical.verification.tier == T.UNVERIFIED
    assert xss.canonical.verification.method == VerificationMethod.REPLAY


@pytest.mark.parametrize("state", ["verified", "refuted", "suppressed"])
def test_findings_that_are_settled_or_suppressed_are_not_replayed(state):
    with serve() as fx:
        xss = case(XSS, f"{fx.url}/search?q=1")
        verification = xss.canonical.verification
        if state == "verified":
            verification.advance(T.REPLAY_VERIFIED)
        elif state == "refuted":
            verification.advance(T.REFUTED)
        else:
            xss.canonical.suppression = Suppression(
                reason="accepted", author="a@b.c", expires="2099-01-01"
            )
        run(fx.url, xss)
    assert fx.seen == []


def test_finding_without_a_parameter_is_skipped_for_injection_oracles():
    with serve() as fx:
        xss = case(XSS, f"{fx.url}/search", parameter="")
        report, _ = run(fx.url, xss)
    assert fx.seen == []
    assert xss.canonical.finding_id in report.skipped


def test_evidence_is_redacted_capped_and_tied_to_the_request_log():
    with serve() as fx:
        cookie = case(XSS, f"{fx.url}/cookie?q=1")
        big = case(XSS, f"{fx.url}/big?q=1", parameter="q")
        with make_client(fx.url) as client:
            replay([cookie, big], client, fast_settings())
            log = {e.request_id: e for e in client.log.entries()}
    evidence = cookie.canonical.verification.evidence
    assert [e.role for e in evidence] == ["probe", "control"]
    assert evidence[0].response_headers["Set-Cookie"] == "[REDACTED]"
    assert all(log[e.request_id].url == e.url for e in evidence)
    assert cookie.canonical.verification.baseline_ref == evidence[1].request_id
    probe = big.canonical.verification.evidence[0]
    assert len(probe.response_body_excerpt) <= 8 * 1024
    assert re.search(r"<haris[0-9a-f]{8}>", probe.response_body_excerpt)


def test_positive_and_refuting_results_rescore_through_the_tier_floor():
    with serve() as fx:
        xss = case(XSS, f"{fx.url}/search?q=1")
        missing = case(
            HEADER,
            f"{fx.url}/hdr",
            scanner="header_checks",
            parameter="X-Frame-Options",
        )
        run(fx.url, xss, missing)
    assert xss.canonical.confidence_score >= 0.9
    assert missing.canonical.confidence_score == 0.0
    assert xss.canonical.verification.timestamp


def test_verify_config_loads_with_spec_defaults_and_known_oracles():
    settings = load_verify_settings()
    assert settings.max_requests == 500
    assert settings.timing.delay_s == 5.0
    assert settings.timing.pairs == 3
    assert settings.llm.abstain_below == 0.7
    assert settings.llm.max_cases == 50
    named = {c.oracle for c in get_registry().classes.values()} - {"none"}
    chain = {n.strip() for c in named for n in c.split(",")}
    assert chain <= set(ORACLES)
    assert set(ORACLES) == {
        "reflection",
        "error_signature",
        "timing",
        "header_presence",
        "canary",
        "soft404",
        "content_validator",
    }
