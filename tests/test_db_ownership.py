from pathlib import Path

import pytest

from haris.db.store import ScanStore
from haris.models import Finding, ScanSession, ScanState, Severity, Target
from haris.models.scan_config_template import ScanConfigTemplate


def _save(
    store: ScanStore,
    sid: str,
    owner: str,
    url: str,
    started: str,
    *,
    state: ScanState = ScanState.COMPLETED,
    severity: Severity = Severity.HIGH,
) -> None:
    finding = Finding(title="t", description="d", severity=severity, finding_id=sid)
    store.save_session(
        ScanSession(
            session_id=sid,
            target=Target(base_url=url),
            started_at=started,
            all_findings=[finding],
            scan_state=state,
        ),
        owner_user_id=owner,
    )


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    store = ScanStore(tmp_path / "own.db")
    _save(store, "a1", "alice", "https://a.example.com", "2026-01-01T00:00:00")
    _save(store, "a2", "alice", "https://shared.example.com", "2026-01-02T00:00:00")
    _save(store, "b1", "bob", "https://shared.example.com", "2026-01-03T00:00:00")
    _save(
        store,
        "b2",
        "bob",
        "https://b.example.com",
        "2026-01-04T00:00:00",
        state=ScanState.RUNNING,
    )
    return store


def test_listing_is_filtered_by_owner(store: ScanStore) -> None:
    mine, total = store.list_sessions_paginated(owner_user_id="alice")
    everything, all_total = store.list_sessions_paginated()

    assert (total, {r["session_id"] for r in mine}) == (2, {"a1", "a2"})
    assert all_total == 4
    assert len(everything) == 4
    assert store.list_sessions_paginated(owner_user_id="nobody")[1] == 0


def test_website_views_are_scoped_and_skip_unfinished_scans(store: ScanStore) -> None:
    bob_hosts = {w["hostname"] for w in store.list_websites("bob")}

    assert bob_hosts == {"shared.example.com"}
    assert [
        s["session_id"]
        for s in store.get_scans_for_hostname("shared.example.com", "bob")
    ] == ["b1"]
    assert len(store.get_scans_for_hostname("shared.example.com")) == 2
    assert store.get_scans_for_hostname("a.example.com", "bob") == []


def test_trends_count_only_the_owners_scans(store: ScanStore) -> None:
    trends = store.get_severity_trends("shared.example.com", "alice")

    assert trends["labels"] == ["2026-01-02"]
    assert trends["datasets"]["high"] == [1]
    assert store.get_severity_trends("shared.example.com")["labels"] == [
        "2026-01-02",
        "2026-01-03",
    ]


def test_dashboard_summary_is_scoped(store: ScanStore) -> None:
    bob = store.dashboard_summary("bob")
    everyone = store.dashboard_summary()

    assert (bob["total_scans"], bob["total_websites"]) == (2, 2)
    assert {f["session_id"] for f in bob["recent_findings"]} == {"b1", "b2"}
    assert everyone["total_scans"] == 4
    assert store.dashboard_summary("nobody")["recent_findings"] == []


def test_template_owner_survives_an_update_without_owner(store: ScanStore) -> None:
    tpl = ScanConfigTemplate(template_id="t1", name="mine")
    store.save_scan_config_template(tpl, owner_user_id="alice")
    store.save_scan_config_template(tpl.model_copy(update={"name": "renamed"}))

    assert store.template_owner("t1") == "alice"
    assert store.template_owner("builtin-01") == ""
    assert store.template_owner("missing") is None
    owners = {
        t["template_id"]: t["owner_user_id"] for t in store.list_scan_config_templates()
    }
    assert owners["t1"] == "alice"
