import sqlite3
from pathlib import Path

import pytest

from haris.core.correlator import FindingCorrelator
from haris.core.identity import assign_identity
from haris.db.store import ScanStore
from haris.models import (
    Finding,
    ScannerResult,
    ScanSession,
    ScanState,
    Severity,
    Target,
    VerificationTier,
)
from haris.models.verification import EvidenceExchange, Suppression

BASE = "https://example.com"
SCHEMA_0_6_2 = Path(__file__).parent / "fixtures" / "haris_0_6_2_schema.sql"


def _finding(scanner: str, observation_id: str) -> Finding:
    finding = Finding(
        title="Missing HSTS header",
        description="No Strict-Transport-Security.",
        severity=Severity.MEDIUM,
        url=BASE,
        cwe_id="CWE-319",
        scanner=scanner,
        observation_id=observation_id,
    )
    assign_identity(finding, BASE)
    return finding


def _session_0_7() -> ScanSession:
    verified = _finding("header_checks", "obs000000001")
    verified.verification.advance(VerificationTier.REPLAY_VERIFIED)
    verified.verification.evidence.append(
        EvidenceExchange(role="probe", url=BASE, status=200)
    )
    suppressed = _finding("header_checks", "obs000000002")
    suppressed.suppression = Suppression(
        reason="accepted risk", author="a@example.com", expires="2027-01-01"
    )
    findings = [verified, suppressed]
    return ScanSession(
        session_id="s07",
        target=Target(base_url=BASE),
        started_at="2026-01-01T00:00:00+00:00",
        scanners_used=["header_checks", "nuclei"],
        scanner_results=[
            ScannerResult(
                scanner_name="header_checks", findings=[verified, suppressed]
            ),
            ScannerResult(scanner_name="nuclei", errors=["x"]),
        ],
        all_findings=findings,
        correlated=FindingCorrelator().correlate(findings, BASE),
        scan_state=ScanState.INCOMPLETE,
    )


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(tmp_path / "id.db")


def test_session_0_7_round_trips_every_new_field(store: ScanStore) -> None:
    session = _session_0_7()
    store.save_session(session)

    loaded = store.load_session("s07")

    assert loaded is not None
    assert [f.to_dict() for f in loaded.all_findings] == [
        f.to_dict() for f in session.all_findings
    ]
    assert loaded.scan_state == ScanState.INCOMPLETE
    assert loaded.scanner_status == session.scanner_status
    assert [
        (c.canonical.to_dict(), c.sources, c.consensus_score) for c in loaded.correlated
    ] == [
        (c.canonical.to_dict(), c.sources, c.consensus_score)
        for c in session.correlated
    ]
    assert loaded.all_findings[0].verification.tier == VerificationTier.REPLAY_VERIFIED
    assert loaded.all_findings[1].suppression is not None
    record = store.get_scan_record("s07")
    assert record is not None
    assert record["scanner_status"] == {
        "header_checks": "completed",
        "nuclei": "failed",
    }


def test_observations_sharing_a_fingerprint_are_both_stored(store: ScanStore) -> None:
    session = _session_0_7()
    first, second = session.all_findings
    assert first.finding_id == second.finding_id

    store.save_session(session)

    loaded = store.load_session("s07")
    assert loaded is not None
    assert [f.observation_id for f in loaded.all_findings] == [
        "obs000000001",
        "obs000000002",
    ]


def test_duplicate_observation_id_in_one_scan_is_rejected(store: ScanStore) -> None:
    session = _session_0_7()
    session.all_findings[1].observation_id = session.all_findings[0].observation_id

    with pytest.raises(sqlite3.IntegrityError):
        store.save_session(session)


def test_resaving_a_session_keeps_owner(store: ScanStore) -> None:
    store.save_session(_session_0_7(), owner_user_id="u1")
    store.save_session(_session_0_7())

    assert store.scan_owner("s07") == "u1"
    assert store.scan_owner("missing") is None


def test_0_6_database_opens_with_owner_backfilled_and_identity_derived(
    tmp_path: Path,
) -> None:
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA_0_6_2.read_text())
    conn.execute("INSERT INTO schema_version (version) VALUES (6)")
    conn.execute(
        "INSERT INTO scans (session_id, target_url, started_by, started_at)"
        " VALUES ('old', 'https://example.com', 'u1', '2026-01-01'),"
        " ('orphan', 'https://example.com', '', '2026-01-02')"
    )
    conn.execute(
        "INSERT INTO findings (session_id, finding_id, title, severity, url, cwe_id)"
        " VALUES ('old', 'rand-id-1', 'Missing HSTS header', 'medium',"
        " 'https://example.com', 'CWE-319')"
    )
    conn.commit()
    conn.close()

    store = ScanStore(db)

    assert store.scan_owner("old") == "u1"
    assert store.scan_owner("orphan") == ""
    session = store.load_session("old")
    assert session is not None
    assert session.scan_state == ScanState.COMPLETED
    legacy = session.all_findings[0]
    assert legacy.finding_id == "rand-id-1"
    assert legacy.observation_id == "rand-id-1"
    assert legacy.fingerprint == _finding("x", "y").fingerprint
