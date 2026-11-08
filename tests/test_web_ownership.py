from collections.abc import Iterator
from pathlib import Path

import pytest

from .test_web_env import WebEnv, stub_scan_runner

LLM_BODY = {"question": "x", "backend": "none"}


@pytest.fixture()
def env(tmp_path: Path) -> Iterator[WebEnv]:
    with pytest.MonkeyPatch.context() as patch:
        stub_scan_runner(patch)
        yield WebEnv(tmp_path)


@pytest.fixture()
def shared_env(tmp_path: Path) -> WebEnv:
    return WebEnv(tmp_path, share_scans=True)


def test_owner_and_admin_read_scan_and_stranger_gets_404(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    url = f"/api/scan/{scan}/status"
    assert env.browser(env.alice).get(url).status_code == 200
    assert env.browser(env.admin).get(url).status_code == 200
    assert env.browser(env.bob).get(url).status_code == 404


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("GET", "/status", None),
        ("GET", "/report/json", None),
        ("GET", "/findings", None),
        ("GET", "/enrichment", None),
        ("POST", "/ask", LLM_BODY),
        ("POST", "/chat", LLM_BODY),
        ("POST", "/summarize", LLM_BODY),
        ("DELETE", "", None),
    ],
)
def test_derived_scan_routes_hide_scan_from_stranger(
    env: WebEnv, method: str, suffix: str, body: dict[str, str] | None
) -> None:
    scan = env.add_scan(env.alice)
    bob = env.browser(env.bob)
    response = bob.request(
        method, f"/api/scan/{scan}{suffix}", json=body, headers=bob.csrf_headers
    )
    assert response.status_code == 404


def test_missing_and_foreign_scans_are_indistinguishable(env: WebEnv) -> None:
    foreign = env.add_scan(env.alice)
    bob = env.browser(env.bob)
    a = bob.get(f"/api/scan/{foreign}/status")
    b = bob.get("/api/scan/does-not-exist/status")
    assert (a.status_code, a.json()) == (b.status_code, b.json())


def test_scan_page_is_hidden_from_stranger(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    assert env.browser(env.bob).get(f"/scan/{scan}").status_code == 404


def test_listing_is_filtered_to_own_scans(env: WebEnv) -> None:
    for _ in range(2):
        env.add_scan(env.alice)
    for _ in range(3):
        env.add_scan(env.bob)
    bob_scans = env.browser(env.bob).get("/api/scans", params={"per_page": 50}).json()
    alice_scans = (
        env.browser(env.alice).get("/api/scans", params={"per_page": 50}).json()
    )
    assert bob_scans["total"] == 3
    assert alice_scans["total"] == 3  # the two above plus the fixture scan
    assert env.browser(env.admin).get("/api/scans").json()["total"] == 6


def test_websites_and_dashboard_are_scoped(env: WebEnv) -> None:
    env.add_scan(env.alice, url="https://alice-only.example.com")
    bob = env.browser(env.bob)
    assert "alice-only.example.com" not in bob.get("/api/websites").text
    assert "alice-only.example.com" not in bob.get("/websites").text
    assert bob.get("/website/alice-only.example.com").status_code == 404
    assert bob.get("/api/website/alice-only.example.com/scans").json() == []
    assert bob.get("/api/dashboard/summary").json()["total_scans"] == 0


def test_started_scan_is_owned_by_starter(env: WebEnv) -> None:
    alice = env.browser(env.alice)
    started = alice.post(
        "/api/scan/start",
        data={"target_url": "https://a.example.com"},
        headers=alice.csrf_headers,
    )
    assert started.status_code == 202
    scan = started.json()["scan_id"]
    assert alice.get(f"/api/scan/{scan}/status").status_code == 200
    assert env.browser(env.bob).get(f"/api/scan/{scan}/status").status_code == 404


def test_conversation_is_hidden_from_other_user_and_admin_reads(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    conversation = env.add_conversation(env.alice, scan)
    url = f"/api/scan/{scan}/chat/{conversation}"
    assert env.browser(env.alice).get(url).status_code == 200
    assert env.browser(env.admin).get(url).status_code == 200
    assert env.browser(env.bob).get(url).status_code == 404
    bob = env.browser(env.bob)
    assert bob.delete(url, headers=bob.csrf_headers).status_code == 404


def test_conversation_of_another_user_is_hidden_even_on_shared_scan(
    shared_env: WebEnv,
) -> None:
    env = shared_env
    scan = env.add_scan(env.alice)
    conversation = env.add_conversation(env.alice, scan)
    bob = env.browser(env.bob)
    assert bob.get(f"/api/scan/{scan}/chat/{conversation}").status_code == 404
    chat = bob.post(
        f"/api/scan/{scan}/chat",
        json={**LLM_BODY, "conversation_id": conversation},
        headers=bob.csrf_headers,
    )
    assert chat.status_code == 404


def test_conversation_cannot_be_read_through_another_scan(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    other = env.add_scan(env.alice)
    conversation = env.add_conversation(env.alice, scan)
    alice = env.browser(env.alice)
    assert alice.get(f"/api/scan/{other}/chat/{conversation}").status_code == 404


def test_shared_scans_are_readable_but_not_deletable(shared_env: WebEnv) -> None:
    env = shared_env
    scan = env.add_scan(env.alice)
    bob = env.browser(env.bob)
    assert bob.get(f"/api/scan/{scan}/status").status_code == 200
    assert bob.get(f"/scan/{scan}").status_code == 200
    assert bob.delete(f"/api/scan/{scan}", headers=bob.csrf_headers).status_code == 403
    assert env.browser(env.alice).get(f"/api/scan/{scan}/status").status_code == 200


def test_shared_listing_shows_every_scan(shared_env: WebEnv) -> None:
    env = shared_env
    env.add_scan(env.bob)
    listing = env.browser(env.bob).get("/api/scans", params={"per_page": 50}).json()
    assert listing["total"] == 2


def test_owner_deletes_own_scan(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    alice = env.browser(env.alice)
    assert (
        alice.delete(f"/api/scan/{scan}", headers=alice.csrf_headers).status_code == 200
    )
    assert alice.get(f"/api/scan/{scan}/status").status_code == 404


def test_sharing_is_off_by_default(env: WebEnv) -> None:
    assert env.settings.share_scans_org_wide is False


def test_unowned_legacy_scan_is_admin_only(env: WebEnv) -> None:
    scan = env.add_scan(None)
    assert env.browser(env.alice).get(f"/api/scan/{scan}/status").status_code == 404
    assert env.browser(env.admin).get(f"/api/scan/{scan}/status").status_code == 200


def test_template_is_hidden_from_other_user(env: WebEnv) -> None:
    template = env.add_template(env.alice)
    url = f"/api/scan-templates/{template}"
    assert env.browser(env.alice).get(url).status_code == 200
    assert env.browser(env.admin).get(url).status_code == 200
    assert env.browser(env.bob).get(url).status_code == 404
    assert template not in env.browser(env.bob).get("/api/scan-templates").text
    assert env.browser(env.bob).get(f"/templates/{template}/edit").status_code == 404


def test_template_write_needs_owner(env: WebEnv) -> None:
    template = env.add_template(env.alice)
    bob = env.browser(env.bob)
    url = f"/api/scan-templates/{template}"
    assert bob.put(url, json={"name": "x"}, headers=bob.csrf_headers).status_code == 404
    assert bob.delete(url, headers=bob.csrf_headers).status_code == 404


def test_builtin_template_is_readable_but_not_writable_by_user(env: WebEnv) -> None:
    template = env.add_template(None)
    bob = env.browser(env.bob)
    url = f"/api/scan-templates/{template}"
    assert bob.get(url).status_code == 200
    assert bob.put(url, json={"name": "x"}, headers=bob.csrf_headers).status_code == 403
    assert bob.delete(url, headers=bob.csrf_headers).status_code == 403
    admin = env.browser(env.admin)
    assert (
        admin.put(url, json={"name": "x"}, headers=admin.csrf_headers).status_code
        == 200
    )


def test_scan_cannot_start_from_foreign_template(env: WebEnv) -> None:
    template = env.add_template(env.alice)
    bob = env.browser(env.bob)
    response = bob.post(
        "/api/scan/start",
        data={"target_url": "https://a.example.com", "template_id": template},
        headers=bob.csrf_headers,
    )
    assert response.status_code == 404


def test_inactive_user_session_is_rejected(env: WebEnv) -> None:
    client = env.browser(env.alice)
    env.state.auth.update_user(env.alice.user_id, is_active=False)
    assert client.get("/api/scans").status_code == 401


def test_deleted_user_session_is_rejected(env: WebEnv) -> None:
    client = env.browser(env.bob)
    env.state.auth.delete_user(env.bob.user_id)
    assert client.get("/api/scans").status_code == 401
