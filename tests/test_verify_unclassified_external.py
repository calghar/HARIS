import pytest

from haris.core.exit_codes import exit_code
from haris.core.risk import assess_risk_posture
from haris.models import (
    RiskPosture,
    ScanSession,
    ScanState,
    Scope,
    Target,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from haris.reporting import REPORTER_REGISTRY
from haris.verify.replay import replay
from tests.test_verify_baseline_oracles import host
from tests.verify_server import case, fast_settings, make_client

T = VerificationTier
M = VerificationMethod
# POST stays allowed so a non-GET row is skipped by the class rule, not by scope.
SCOPE = Scope(
    rate_limit_rps=1000.0,
    allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
)
TITLES = {
    "nikto": "This might be interesting.",
    "nuclei": "GoCD cipher suite",
    "header_checks": "PostgreSQL history file",
}
FTP_BODY = "unique ftp listing that matches no control\n"


@pytest.mark.parametrize(
    ("scanner", "method", "path", "catch_all", "body", "tier", "replay_method"),
    [
        ("nikto", "GET", "/.psql_history", True, None, T.REFUTED, M.REPLAY),
        ("nuclei", "GET", "/ftp/", False, FTP_BODY, T.UNVERIFIED, M.REPLAY),
        ("nikto", "GET", "/admin/", True, None, T.REFUTED, M.REPLAY),
        ("nikto", "GET", "/", True, None, T.UNVERIFIED, M.NONE),
        ("nikto", "POST", "/api/x", True, None, T.UNVERIFIED, M.NONE),
        (
            "header_checks",
            "GET",
            "/.psql_history",
            True,
            None,
            T.UNVERIFIED,
            M.NONE,
        ),
    ],
    ids=[
        "psql-history-matches-control",
        "ftp-differs-from-controls",
        "admin-matches-control",
        "root-not-sent",
        "post-not-sent",
        "builtin-not-sent",
    ],
)
def test_unclassified_external_finding(
    scanner: str,
    method: str,
    path: str,
    catch_all: bool,
    body: str | None,
    tier: VerificationTier,
    replay_method: VerificationMethod,
) -> None:
    """Scenario: Unclassified external finding."""
    files: dict[str, tuple[str, str]] = {}
    if body is not None:
        files[path] = (body, "text/plain")
    with host(catch_all=catch_all, files=files) as url:
        finding = case(
            TITLES[scanner],
            f"{url}{path}",
            scanner=scanner,
            parameter="",
            method=method,
        )
        with make_client(url, SCOPE) as client:
            replay([finding], client, fast_settings())
            sent = [entry.url for entry in client.log.entries()]
    verification = finding.canonical.verification
    assert finding.canonical.vuln_class.startswith(f"unclassified:{scanner}:")
    assert verification.tier == tier
    assert verification.method == replay_method
    if replay_method == M.REPLAY:
        assert verification.oracle == VerificationOracle.SOFT404
        assert any(path in entry for entry in sent)
    else:
        assert sent == []


def test_refuted_external_finding_stays_visible() -> None:
    """Scenario: Refuted external finding stays visible."""
    with host(catch_all=True, files={}) as url:
        finding = case(
            TITLES["nikto"],
            f"{url}/.psql_history",
            scanner="nikto",
            parameter="",
        )
        with make_client(url) as client:
            replay([finding], client, fast_settings())
        canonical = finding.canonical
        session = ScanSession(
            session_id="s",
            target=Target(base_url=url),
            scan_state=ScanState.COMPLETED,
            all_findings=[canonical],
            correlated=[finding],
            risk_posture=assess_risk_posture([finding]),
        )
    assert canonical.verification.tier == T.REFUTED
    assert canonical.is_active is False
    assert session.risk_posture == RiskPosture.EXCELLENT
    assert exit_code(session, canonical.severity) == 0
    for reporter in REPORTER_REGISTRY.values():
        text = reporter().generate(session)
        assert canonical.title in text
        assert "refuted" in text
