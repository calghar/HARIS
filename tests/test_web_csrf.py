import re
from collections.abc import Iterator
from typing import Any

import pytest

from haris.auth.cookies import SEED_COOKIE, SESSION_COOKIE
from haris.auth.redirects import redirect_to_next, safe_next
from haris.db.connection import connect

from .test_web_env import PASSWORD, Browser, Resources, WebEnv, stub_scan_runner
from .test_web_routes import CASES, UNSAFE, Case, case_json, reached

UNSAFE_CASES = [c for c in CASES if c.method in UNSAFE]
TOKEN_FIELD = re.compile(r'name="csrf_token" value="([0-9a-f]+)"')
START_FORM = {"target_url": "https://a.example.com"}


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[WebEnv]:
    with pytest.MonkeyPatch.context() as patch:
        stub_scan_runner(patch)
        yield WebEnv(tmp_path_factory.mktemp("csrf"))


def _name(case: Case) -> str:
    return f"{case.method} {case.path}"


def _request(
    client: Browser,
    case: Case,
    resources: Resources,
    headers: dict[str, str] | None = None,
    extra_data: dict[str, str] | None = None,
) -> Any:
    data = {**(case.data or {}), **(extra_data or {})} if case.data else extra_data
    return client.request(
        case.method,
        case.path.format_map(resources),
        json=case_json(case, resources),
        data=data,
        headers=headers or {},
    )


@pytest.mark.parametrize("case", UNSAFE_CASES, ids=_name)
def test_missing_token_is_forbidden(env: WebEnv, case: Case) -> None:
    resources = env.resources(env.admin)
    response = _request(env.browser(env.admin), case, resources)
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}


@pytest.mark.parametrize("case", UNSAFE_CASES, ids=_name)
def test_wrong_token_is_forbidden(env: WebEnv, case: Case) -> None:
    resources = env.resources(env.admin)
    headers = {"X-CSRF-Token": "0" * 64}
    assert _request(env.browser(env.admin), case, resources, headers).status_code == 403


@pytest.mark.parametrize("case", UNSAFE_CASES, ids=_name)
def test_header_token_is_accepted(env: WebEnv, case: Case) -> None:
    client = env.browser(env.admin)
    response = _request(client, case, env.resources(env.admin), client.csrf_headers)
    assert reached(response.status_code, case)


@pytest.mark.parametrize("case", [c for c in UNSAFE_CASES if c.data], ids=_name)
def test_form_field_token_is_accepted(env: WebEnv, case: Case) -> None:
    client = env.browser(env.admin)
    response = _request(
        client, case, env.resources(env.admin), extra_data={"csrf_token": client.csrf}
    )
    assert reached(response.status_code, case)


def test_rejected_request_does_not_run_handler(env: WebEnv) -> None:
    client = env.browser(env.alice)
    before = len(env.state.store.list_sessions())
    response = client.post("/api/v1/scans", data=START_FORM)
    assert response.status_code == 403
    assert len(env.state.store.list_sessions()) == before


def test_token_of_another_session_is_rejected(env: WebEnv) -> None:
    alice, bob = env.browser(env.alice), env.browser(env.bob)
    response = alice.post("/api/v1/scans", data=START_FORM, headers=bob.csrf_headers)
    assert response.status_code == 403


def test_token_is_not_accepted_as_cookie(env: WebEnv) -> None:
    client = env.browser(env.alice)
    client.cookies.set("csrf_token", client.csrf)
    assert client.post("/api/v1/scans", data=START_FORM).status_code == 403


def test_get_needs_no_token(env: WebEnv) -> None:
    assert env.browser(env.alice).get("/api/v1/scans").status_code == 200


def test_anonymous_post_to_public_route_needs_token(env: WebEnv) -> None:
    anon = env.anonymous()
    form = {"email": "alice@example.com", "password": PASSWORD}
    assert anon.post("/login", data=form).status_code == 403


def test_login_with_seed_token_sets_hardened_session_cookie(env: WebEnv) -> None:
    anon = env.anonymous()
    page = anon.get("/login")
    assert page.status_code == 200
    seed = page.headers["set-cookie"]
    assert seed.startswith(f"{SEED_COOKIE}=")
    assert "HttpOnly" in seed
    assert "SameSite=lax" in seed
    token = TOKEN_FIELD.search(page.text)
    assert token
    response = anon.post(
        "/login",
        data={
            "email": "alice@example.com",
            "password": PASSWORD,
            "csrf_token": token.group(1),
        },
    )
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" not in cookie


def test_session_cookie_is_secure_over_https(env: WebEnv) -> None:
    anon = env.anonymous()
    anon.base_url = anon.base_url.copy_with(scheme="https")
    page = anon.get("/login")
    token = TOKEN_FIELD.search(page.text)
    assert token
    assert "Secure" in page.headers["set-cookie"]
    response = anon.post(
        "/login",
        data={
            "email": "alice@example.com",
            "password": PASSWORD,
            "csrf_token": token.group(1),
        },
    )
    assert "Secure" in response.headers["set-cookie"]


def test_logout_needs_token(env: WebEnv) -> None:
    client = env.browser(env.alice)
    assert client.post("/auth/logout").status_code == 403
    assert client.get("/api/v1/scans").status_code == 200
    response = client.post("/auth/logout", headers=client.csrf_headers)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    client.cookies.clear()
    assert client.get("/api/v1/scans").status_code == 401


def test_pages_embed_the_session_token(env: WebEnv) -> None:
    client = env.browser(env.alice)
    page = client.get("/scans").text
    assert f'<meta name="csrf-token" content="{client.csrf}">' in page


def _login(env: WebEnv, next_value: str | None) -> str:
    with connect(env.settings.db_path) as conn:
        conn.execute("DELETE FROM auth_attempt_counters")
    anon = env.anonymous()
    token = TOKEN_FIELD.search(anon.get("/login").text)
    assert token
    data = {
        "email": "alice@example.com",
        "password": PASSWORD,
        "csrf_token": token.group(1),
    }
    if next_value is not None:
        data["next"] = next_value
    response = anon.post("/login", data=data)
    assert response.status_code == 303
    return response.headers["location"]


@pytest.mark.parametrize(
    ("next_value", "location"),
    [
        ("/scan/abc", "/scan/abc"),
        ("//evil.test/x", "/"),
        ("/\\evil.test", "/"),
        ("https://evil.test/", "/"),
        ("/%0d%0aevil", "/%0d%0aevil"),
        ("/a\tb", "/"),
        ("javascript:alert(1)", "/"),
        (None, "/"),
    ],
)
def test_login_redirect_is_same_origin(
    env: WebEnv, next_value: str | None, location: str
) -> None:
    """Scenario Outline: Safe next parameter."""
    assert _login(env, next_value) == location


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/scans?page=2", "/scans?page=2"),
        ("", "/"),
        (None, "/"),
        ("scans", "/"),
        ("///evil.test", "/"),
        ("/\\/evil.test", "/"),
        ("/ok\r\nSet-Cookie: x=1", "/"),
    ],
)
def test_safe_next(target: str | None, expected: str) -> None:
    assert safe_next(target) == expected
    response = redirect_to_next(target)
    assert response.status_code == 303
    assert response.headers["location"] == expected


def test_anonymous_page_redirects_to_login_with_next(env: WebEnv) -> None:
    response = env.anonymous().get("/scan/abc123?tab=ask")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/scan/abc123%3Ftab%3Dask"


def test_logged_in_user_on_login_page_follows_safe_next(env: WebEnv) -> None:
    client = env.browser(env.alice)
    response = client.get("/login", params={"next": "//evil.test"})
    assert response.status_code == 303
    assert response.headers["location"] == "/"
