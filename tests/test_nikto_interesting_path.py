import json

import pytest

from haris.core.correlator import FindingCorrelator
from haris.core.vuln_class import get_registry
from haris.models import (
    CorrelatedFinding,
    Finding,
    ScanSession,
    ScanState,
    Severity,
    Target,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from haris.reporting import REPORTER_REGISTRY
from haris.scanners.nikto_scanner import INTERESTING_PATH_CLASS, NiktoScanner
from haris.verify.replay import oracle_names, replay, replayable
from tests.test_verify_baseline_oracles import host
from tests.verify_server import fast_settings, make_client

BASE_URL = "http://127.0.0.1:3000"
FTP_ITEM = "/ftp/: This might be interesting."


def nikto_findings(url: str, msg: str) -> list[Finding]:
    report = [
        {
            "host": "127.0.0.1",
            "ip": "127.0.0.1",
            "port": "3000",
            "vulnerabilities": [
                {"id": "999999", "method": "GET", "url": url, "msg": msg}
            ],
        }
    ]
    return NiktoScanner().parse_results(json.dumps(report), base_url=BASE_URL)


def correlated_ftp() -> CorrelatedFinding:
    return FindingCorrelator().correlate(
        nikto_findings("/ftp/", "This might be interesting."), BASE_URL
    )[0]


@pytest.mark.parametrize(
    "msg",
    [
        "This might be interesting.",
        FTP_ITEM,
        "/debug/: This might be interesting.",
        "/backup/: This might be interesting.",
    ],
    ids=["bare", "path-prefixed", "debug-keyword", "backup-keyword"],
)
def test_interesting_path_is_classified_and_info(msg: str) -> None:
    """Scenario: Nikto interesting path."""
    (finding,) = nikto_findings("/ftp/", msg)
    assert finding.vuln_class == INTERESTING_PATH_CLASS
    assert finding.severity == Severity.INFO


def test_other_nikto_messages_keep_their_class_and_severity() -> None:
    (mid_sentence,) = nikto_findings("/x", "Header says: this might be interesting.")
    (listing,) = nikto_findings("/admin/", "Directory indexing found.")
    assert mid_sentence.vuln_class == ""
    assert (listing.vuln_class, listing.severity) == ("", Severity.MEDIUM)


def test_class_and_severity_survive_correlation() -> None:
    canonical = correlated_ftp().canonical
    assert canonical.vuln_class == INTERESTING_PATH_CLASS
    assert canonical.severity == Severity.INFO
    assert INTERESTING_PATH_CLASS not in get_registry().classes


def test_interesting_path_reaches_every_report_format() -> None:
    """Scenario: Nikto interesting path."""
    case = correlated_ftp()
    session = ScanSession(
        session_id="s",
        target=Target(base_url=BASE_URL),
        scan_state=ScanState.COMPLETED,
        all_findings=[case.canonical],
        correlated=[case],
    )
    for name, reporter in REPORTER_REGISTRY.items():
        text = reporter().generate(session)
        assert case.canonical.title in text, name
        if name in {"json", "csv", "sarif"}:
            assert INTERESTING_PATH_CLASS in text, name


def test_interesting_path_is_replayed_by_the_soft404_oracle() -> None:
    case = correlated_ftp()
    assert oracle_names(case, BASE_URL) == ["soft404"]
    assert replayable(case, {"GET"}, BASE_URL)
    assert not replayable(case, {"POST"}, BASE_URL)


def test_interesting_path_matching_the_catch_all_page_is_refuted() -> None:
    with host(catch_all=True, files={}) as url:
        (finding,) = nikto_findings("/ftp/", "This might be interesting.")
        finding.url = f"{url}/ftp/"
        case = FindingCorrelator().correlate([finding], url)[0]
        with make_client(url) as client:
            replay([case], client, fast_settings())
    verification = case.canonical.verification
    assert verification.tier == VerificationTier.REFUTED
    assert verification.method == VerificationMethod.REPLAY
    assert verification.oracle == VerificationOracle.SOFT404


def test_catch_all_response_refutes_the_gocd_template_match() -> None:
    finding = Finding(
        title="GoCD Encryption Key",
        description="",
        severity=Severity.HIGH,
        scanner="nuclei",
        tags=["security_misconfiguration"],
        raw_data={"template-id": "gocd-encryption-key"},
    )
    with host(catch_all=True, files={}) as url:
        finding.url = f"{url}/go/add-on/business-continuity/api/cipher.aes"
        case = FindingCorrelator().correlate([finding], url)[0]
        with make_client(url) as client:
            replay([case], client, fast_settings())
    assert case.canonical.vuln_class == "sensitive_file"
    assert case.canonical.verification.tier == VerificationTier.REFUTED
