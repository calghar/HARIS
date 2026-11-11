import hashlib
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from haris.db.connection import connect

from .test_web_env import WebEnv, stub_scan_runner
from .test_web_routes import app_routes

TOKEN_FORMAT = re.compile(r"^haris_pat_[A-Za-z0-9_-]{43}$")
START = {"target_url": "https://app.example.com"}


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[WebEnv]:
    stub_scan_runner(monkeypatch)
    yield WebEnv(tmp_path)


def request(client: Any, spec: str) -> httpx.Response:
    method, path = spec.split(" ", 1)
    data = START if method == "POST" and path == "/api/v1/scans" else None
    response: httpx.Response = client.request(method, path, data=data)
    return response


TOKEN_MATRIX = [
    ("scans:read", "valid", "GET /api/v1/scans", 200),
    ("scans:read", "valid", "POST /api/v1/scans", 403),
    ("scans:read,scans:write", "valid", "POST /api/v1/scans", 202),
    ("scans:read", "expired", "GET /api/v1/scans", 401),
    ("scans:read", "revoked", "GET /api/v1/scans", 401),
    ("scans:read", "valid", "GET /", 303),
    ("admin", "valid, user role user", "GET /api/v1/admin/users", 403),
    ("admin", "valid, admin role", "GET /api/v1/admin/users", 200),
    ("scans:read", "valid", "GET /api/v1/tokens", 403),
    ("scans:write", "valid", "GET /api/v1/scans", 403),
    ("scans:read", "valid", "GET /scans", 303),
    ("scans:read", "valid", "GET /auth/profile", 303),
    ("targets:write", "valid", "GET /api/v1/scans", 403),
]


@pytest.mark.parametrize(("scopes", "state", "spec", "status"), TOKEN_MATRIX)
def test_token_matrix(
    env: WebEnv, scopes: str, state: str, spec: str, status: int
) -> None:
    """Scenario Outline: Token matrix."""
    user = env.admin if "admin role" in state else env.alice
    client = env.bearer(user, tuple(scopes.split(",")))
    if state == "expired":
        env.expire_token(client.token_id)
    if state == "revoked":
        assert env.state.tokens.revoke(client.token_id, user.user_id)
    assert request(client, spec).status_code == status


def create(client: Any, **body: Any) -> httpx.Response:
    payload = {"name": "ci", "scopes": ["scans:read"], **body}
    response: httpx.Response = client.post(
        "/api/v1/tokens", json=payload, headers=client.csrf_headers
    )
    return response


@pytest.mark.parametrize("days", [400, 366, 0, -1])
def test_expiry_bounds_reject_out_of_range(env: WebEnv, days: int) -> None:
    """Scenario: Expiry bounds."""
    assert create(env.browser(env.alice), expires_in_days=days).status_code == 422


@pytest.mark.parametrize("days", [1, 365])
def test_expiry_bounds_accept_the_limits(env: WebEnv, days: int) -> None:
    response = create(env.browser(env.alice), expires_in_days=days)
    assert response.status_code == 201
    expires = datetime.fromisoformat(response.json()["expires_at"])
    delta = expires - datetime.now(UTC)
    assert timedelta(days=days) - timedelta(minutes=1) < delta <= timedelta(days=days)


def test_default_expiry_is_ninety_days(env: WebEnv) -> None:
    body = create(env.browser(env.alice)).json()
    delta = datetime.fromisoformat(body["expires_at"]) - datetime.now(UTC)
    assert timedelta(days=89, hours=23) < delta <= timedelta(days=90)


@pytest.mark.parametrize(
    "body",
    [
        {"scopes": []},
        {"scopes": ["root"]},
        {"name": ""},
        {"scopes": ["scans:read", "everything"]},
    ],
)
def test_invalid_token_requests_are_rejected(env: WebEnv, body: dict[str, Any]) -> None:
    assert create(env.browser(env.alice), **body).status_code == 422


def test_token_has_the_specified_format_and_prefix(env: WebEnv) -> None:
    body = create(env.browser(env.alice), scopes=["scans:read", "scans:write"]).json()
    assert TOKEN_FORMAT.match(body["token"])
    assert body["token_prefix"] == body["token"][:12]
    assert body["scopes"] == ["scans:read", "scans:write"]
    assert body["last_used_at"] == ""
    assert body["revoked_at"] == ""


def test_plaintext_is_not_stored(env: WebEnv) -> None:
    """Scenario: Plaintext is not stored."""
    token = create(env.browser(env.alice)).json()["token"]
    with connect(env.settings.db_path) as conn:
        dump = "\n".join(conn.iterdump())
        stored = conn.execute("SELECT token_hash FROM api_tokens").fetchall()
    assert token not in dump
    assert hashlib.sha256(token.encode()).hexdigest() in [r[0] for r in stored]


def test_token_listing_never_returns_secrets(env: WebEnv) -> None:
    alice = env.browser(env.alice)
    token = create(alice).json()["token"]
    listing = alice.get("/api/v1/tokens")
    assert listing.status_code == 200
    assert token not in listing.text
    assert "token_hash" not in listing.text
    assert [t["name"] for t in listing.json()] == ["ci"]
    assert env.browser(env.bob).get("/api/v1/tokens").json() == []


def test_token_use_is_recorded_and_revocation_is_immediate(env: WebEnv) -> None:
    alice = env.browser(env.alice)
    created = create(alice).json()
    bearer = env.anonymous()
    bearer.headers["Authorization"] = f"Bearer {created['token']}"
    assert bearer.get("/api/v1/scans").status_code == 200
    listed = alice.get("/api/v1/tokens").json()[0]
    assert listed["last_used_at"] != ""
    revoked = alice.delete(
        f"/api/v1/tokens/{created['token_id']}", headers=alice.csrf_headers
    )
    assert revoked.status_code == 204
    assert bearer.get("/api/v1/scans").status_code == 401
    again = alice.delete(
        f"/api/v1/tokens/{created['token_id']}", headers=alice.csrf_headers
    )
    assert again.status_code == 404


def test_a_user_cannot_revoke_another_users_token(env: WebEnv) -> None:
    created = create(env.browser(env.alice)).json()
    bob = env.browser(env.bob)
    response = bob.delete(
        f"/api/v1/tokens/{created['token_id']}", headers=bob.csrf_headers
    )
    assert response.status_code == 404
    assert env.state.tokens.authenticate(created["token"]) is not None


def test_a_token_cannot_mint_or_revoke_tokens(env: WebEnv) -> None:
    client = env.bearer(
        env.alice, ("scans:read", "scans:write", "targets:write", "admin")
    )
    assert create(client).status_code == 403
    assert client.get("/api/v1/tokens").status_code == 403
    assert client.delete(f"/api/v1/tokens/{client.token_id}").status_code == 403


@pytest.mark.parametrize(
    "header",
    ["Bearer haris_pat_" + "x" * 43, "Bearer ", "Bearer not-a-token", "Basic abc"],
)
def test_invalid_bearer_credentials_are_rejected(env: WebEnv, header: str) -> None:
    client = env.anonymous()
    response = client.get("/api/v1/scans", headers={"Authorization": header})
    assert response.status_code == 401
    if header.lower().startswith("bearer"):
        assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_bearer_token_beats_a_valid_cookie(env: WebEnv) -> None:
    client = env.browser(env.alice)
    response = client.get(
        "/api/v1/scans", headers={"Authorization": "Bearer haris_pat_" + "x" * 43}
    )
    assert response.status_code == 401


def test_token_is_not_accepted_on_html_pages(env: WebEnv) -> None:
    client = env.bearer(env.alice)
    assert client.get("/scans").status_code == 303
    assert client.get("/api/v1/scans").status_code == 200


def test_token_of_an_inactive_user_is_rejected(env: WebEnv) -> None:
    client = env.bearer(env.alice)
    env.state.auth.update_user(env.alice.user_id, is_active=False)
    assert client.get("/api/v1/scans").status_code == 401


def test_token_of_a_deleted_user_is_rejected(env: WebEnv) -> None:
    client = env.bearer(env.bob)
    env.state.auth.delete_user(env.bob.user_id)
    assert client.get("/api/v1/scans").status_code == 401


def test_ownership_rules_apply_to_the_token_user(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    assert env.bearer(env.alice).get(f"/api/v1/scans/{scan}").status_code == 200
    assert env.bearer(env.bob).get(f"/api/v1/scans/{scan}").status_code == 404
    listing = env.bearer(env.bob).get("/api/v1/scans").json()
    assert scan not in {s["session_id"] for s in listing["scans"]}


def test_user_role_is_not_raised_by_the_admin_scope(env: WebEnv) -> None:
    client = env.bearer(env.bob, ("admin", "scans:read"))
    assert client.get("/api/v1/admin/users").status_code == 403
    assert client.post("/api/v1/templates/update", json={}).status_code == 403


def test_admin_role_needs_the_admin_scope_on_a_token(env: WebEnv) -> None:
    assert env.bearer(env.admin).get("/api/v1/admin/users").status_code == 403
    scoped = env.bearer(env.admin, ("scans:read", "admin"))
    assert scoped.get("/api/v1/admin/users").status_code == 200


CSRF_MATRIX = [
    ("header X-CSRF-Token T", "session cookie", 202),
    ("form field csrf_token T", "session cookie", 202),
    ("header X-CSRF-Token wrong", "session cookie", 403),
    ("(absent)", "session cookie", 403),
    ("(absent)", "Bearer token with scans:write", 202),
]


@pytest.mark.parametrize(("csrf", "auth", "status"), CSRF_MATRIX)
def test_csrf_matrix(env: WebEnv, csrf: str, auth: str, status: int) -> None:
    """Scenario Outline: CSRF matrix."""
    if auth.startswith("Bearer"):
        client: Any = env.bearer(env.alice, ("scans:read", "scans:write"))
    else:
        client = env.browser(env.alice)
    headers: dict[str, str] = {}
    data = dict(START)
    if csrf == "header X-CSRF-Token T":
        headers["X-CSRF-Token"] = client.csrf
    elif csrf == "form field csrf_token T":
        data["csrf_token"] = client.csrf
    elif csrf == "header X-CSRF-Token wrong":
        headers["X-CSRF-Token"] = "0" * 64
    assert (
        client.post("/api/v1/scans", data=data, headers=headers).status_code == status
    )


def test_bearer_requests_skip_csrf_even_with_a_cookie_present(env: WebEnv) -> None:
    client = env.browser(env.alice)
    record, token = env.state.tokens.create(
        env.alice.user_id, "t", ["scans:read", "scans:write"]
    )
    response = client.post(
        "/api/v1/scans", data=START, headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 202
    assert record.token_id


def test_bearer_header_does_not_bypass_csrf_outside_the_api(env: WebEnv) -> None:
    client = env.browser(env.alice)
    _, token = env.state.tokens.create(env.alice.user_id, "t", ["scans:write"])
    response = client.post(
        "/auth/profile",
        data={"display_name": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_legacy_api_paths_are_gone(env: WebEnv) -> None:
    """Scenario: Legacy path removed."""
    alice = env.browser(env.alice)
    scan = env.add_scan(env.alice)
    assert alice.get("/api/scans").status_code == 404
    legacy = [
        ("GET", f"/api/scan/{scan}/status"),
        ("GET", f"/api/scan/{scan}/report/json"),
        ("POST", "/api/scan/start"),
        ("DELETE", f"/api/scan/{scan}"),
        ("GET", "/api/websites"),
        ("GET", "/api/llm/backends"),
        ("GET", "/api/templates/status"),
        ("GET", "/api/scan-templates"),
        ("GET", "/api/dashboard/summary"),
    ]
    for method, path in legacy:
        response = alice.request(method, path, headers=alice.csrf_headers)
        assert response.status_code == 404, path


def test_every_json_route_lives_under_api_v1(env: WebEnv) -> None:
    paths = {path for _, path, _ in app_routes(env)}
    api = {p for p in paths if p.startswith("/api")}
    assert api
    assert all(p.startswith("/api/v1/") for p in api)


def test_scan_delete_returns_no_content(env: WebEnv) -> None:
    scan = env.add_scan(env.alice)
    alice = env.browser(env.alice)
    response = alice.delete(f"/api/v1/scans/{scan}", headers=alice.csrf_headers)
    assert response.status_code == 204
    assert response.content == b""


def test_inactive_user_session_is_rejected_on_the_versioned_api(env: WebEnv) -> None:
    """Scenario: Inactive user."""
    client = env.browser(env.alice)
    env.state.auth.update_user(env.alice.user_id, is_active=False)
    assert client.get("/api/v1/scans").status_code == 401


@pytest.mark.parametrize(("role", "status"), [("admin", 200), ("user", 403)])
def test_admin_routes(env: WebEnv, role: str, status: int) -> None:
    """Scenario Outline: Admin routes."""
    user = env.admin if role == "admin" else env.alice
    assert env.browser(user).get("/api/v1/admin/users").status_code == status


def test_admin_user_list_never_exposes_password_hashes(env: WebEnv) -> None:
    body = env.browser(env.admin).get("/api/v1/admin/users")
    assert body.status_code == 200
    assert "password_hash" not in body.text
    assert {u["email"] for u in body.json()} >= {"alice@example.com"}
