import pytest

from haris.cli_parser import build_parser
from haris.core.engine import ScanEngine
from haris.core.exit_codes import EXIT_USAGE
from haris.core.runner import ScanRunner
from haris.core.scanner import BaseScanner
from haris.ignore import IgnoreFile
from haris.models import (
    Finding,
    ScannerResult,
    ScanSession,
    Scope,
    Severity,
    Target,
    VerificationMethod,
    VerificationTier,
)
from haris.models.scan_context import ScanContext
from haris.net import NetworkPolicy
from haris.verify import DEFAULT_VERIFY_MODE, VerifyMode, run_verification
from tests.test_verify_llm import answer, make_case, provider
from tests.verify_server import fast_settings, make_client, serve

T = VerificationTier
XSS = "Cross Site Scripting"


class Stub(BaseScanner):
    name = "wapiti"
    version = "0"

    def __init__(self, findings: list[Finding]) -> None:
        super().__init__()
        self.findings = findings

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        return ScannerResult(scanner_name=self.name, findings=list(self.findings))

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []


def xss_at(url: str) -> Finding:
    return Finding(
        title=XSS,
        description="",
        severity=Severity.HIGH,
        url=url,
        parameter="q",
        scanner="wapiti",
    )


def engine_run(url: str, mode: VerifyMode | None, **extra: object) -> ScanSession:
    kwargs: dict[str, object] = {} if mode is None else {"verify": mode}
    engine = ScanEngine(
        scanners=[Stub([xss_at(f"{url}/search?q=1")])],
        network_policy=NetworkPolicy(allow_private=True),
        **kwargs,  # type: ignore[arg-type]  # keyword names are fixed above
        **extra,  # type: ignore[arg-type]  # forwarded engine options
    )
    return engine.run(Target(base_url=url, scope=Scope(rate_limit_rps=1000.0)))


def test_engine_verifies_before_risk_when_replay_is_on():
    with serve() as fx:
        session = engine_run(fx.url, VerifyMode.REPLAY)
    canonical = session.correlated[0].canonical
    assert canonical.verification.tier == T.REPLAY_VERIFIED
    assert session.all_findings[0].verification.tier == T.REPLAY_VERIFIED
    assert session.all_findings[0].confidence_score >= 0.9
    assert session.risk_posture.value != "excellent"


def test_engine_default_sends_no_verification_traffic():
    with serve() as fx:
        session = engine_run(fx.url, None)
    assert fx.seen == []
    assert session.correlated[0].canonical.verification.tier == T.UNVERIFIED


def test_suppressed_finding_is_not_verified():
    """Scenario: Suppressed finding is not verified."""
    ignore = IgnoreFile.model_validate(
        {
            "version": 1,
            "ignores": [
                {
                    "rule": "xss_reflected",
                    "reason": "accepted",
                    "author": "qa",
                    "expires": "2099-01-31",
                }
            ],
        }
    )
    with serve() as fx:
        session = engine_run(fx.url, VerifyMode.REPLAY, ignore=ignore)
    canonical = session.correlated[0].canonical
    assert fx.seen == []
    assert canonical.suppression is not None
    assert canonical.verification.tier == T.UNVERIFIED
    assert canonical.verification.method == VerificationMethod.NONE


def test_refuted_findings_stay_in_the_output():
    with serve() as fx:
        missing = Finding(
            title="Missing X-Frame-Options header",
            description="",
            severity=Severity.LOW,
            url=f"{fx.url}/hdr",
            parameter="X-Frame-Options",
            scanner="header_checks",
        )
        engine = ScanEngine(
            scanners=[Stub([missing])],
            network_policy=NetworkPolicy(allow_private=True),
            verify=VerifyMode.REPLAY,
        )
        session = engine.run(
            Target(base_url=fx.url, scope=Scope(rate_limit_rps=1000.0))
        )
    assert [c.canonical.verification.tier for c in session.correlated] == [T.REFUTED]
    assert [f.verification.tier for f in session.all_findings] == [T.REFUTED]


def session_with(url: str) -> ScanSession:
    cases = [make_case(0), make_case(1)]
    for case in cases:
        case.canonical.vuln_class = "xss_reflected"
        case.canonical.url = f"{url}/search?q=1"
        case.canonical.parameter = "q"
        case.canonical.verification.evidence = case.canonical.verification.evidence[:0]
    return ScanSession(
        session_id="s",
        target=Target(base_url=url),
        correlated=cases,
        all_findings=[c.canonical.model_copy(deep=True) for c in cases],
    )


def test_replay_cap_is_reported_in_session_errors():
    with serve() as fx:
        session = session_with(fx.url)
        with make_client(fx.url) as client:
            run_verification(
                session,
                client,
                VerifyMode.REPLAY,
                settings=fast_settings(max_requests=2),
            )
    assert len(fx.seen) == 2
    assert any("[verify] 1 finding(s) not replayed" in e for e in session.errors)
    assert len(session.correlated) == len(session.all_findings) == 2


def test_llm_mode_judges_only_cases_replay_left_unverified():
    with serve() as fx:
        session = session_with(fx.url)
        session.correlated[1].canonical.url = f"{fx.url}/encoded?q=1"
        backend = provider(
            lambda cid: answer(cid, spans=[{"exchange_index": 0, "text": "searched"}])
        )
        with make_client(fx.url) as client:
            run_verification(session, client, VerifyMode.LLM, backend, fast_settings())
    verified, unverified = (c.canonical.verification for c in session.correlated)
    assert verified.tier == T.REPLAY_VERIFIED
    assert verified.llm is None
    assert unverified.tier == T.UNVERIFIED
    assert unverified.llm is not None
    assert len(backend.requests) == 1


def test_llm_mode_without_a_backend_is_reported_not_fatal():
    with serve() as fx:
        session = session_with(fx.url)
        with make_client(fx.url) as client:
            run_verification(session, client, VerifyMode.LLM, None, fast_settings())
    assert any("no LLM backend" in e for e in session.errors)
    assert session.correlated[0].canonical.verification.tier == T.REPLAY_VERIFIED


def test_off_mode_does_nothing():
    with serve() as fx:
        session = session_with(fx.url)
        with make_client(fx.url) as client:
            run_verification(session, client, "off", settings=fast_settings())
    assert fx.seen == []


def test_cli_flag_defaults_to_replay_and_rejects_unknown_values():
    parser = build_parser()
    assert parser.parse_args(["--url", "https://x.test"]).verify == "replay"
    assert DEFAULT_VERIFY_MODE == VerifyMode.REPLAY
    assert parser.parse_args(["--verify", "llm"]).verify == "llm"
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--verify", "always"])
    assert exc.value.code == EXIT_USAGE


def test_runner_passes_the_mode_to_the_engine_and_defaults_to_off():
    target = Target(base_url="https://x.test")
    assert ScanRunner(target)._engine_options["verify"] == VerifyMode.OFF
    llm = ScanRunner(target, verify=VerifyMode.LLM)
    assert llm._engine_options["verify"] == VerifyMode.LLM
