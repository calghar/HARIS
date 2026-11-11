import logging
import re
from pathlib import Path

import pytest

from haris.auth.cookies import SEED_COOKIE, SESSION_COOKIE
from haris.auth.middleware import _LOGIN_MAX_ATTEMPTS
from haris.auth.models import UserRole
from haris.models.scan_config_template import ScanConfigTemplate

from .test_web_env import PASSWORD, Browser, WebEnv

SUCCESS = "If your account exists and is unverified, a new link has been sent."
CSRF_FIELD = re.compile(r'name="csrf_token" value="([0-9a-f]+)"')
VERIFY_URL = re.compile(r"https?://\S+/auth/verify-email\?token=([^\s]+)")


def _csrf(client: Browser, path: str = "/login") -> str:
    page = client.get(path)
    match = CSRF_FIELD.search(page.text)
    assert match is not None, page.status_code
    return match.group(1)


def test_h1_admin_disabled_user_cannot_reactivate_by_verification(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    env = WebEnv(tmp_path)
    disabled = env.state.auth.create_user(
        "disabled@example.com", PASSWORD, is_active=False
    )
    unverified = env.state.auth.create_user(
        "unverified@example.com", PASSWORD, is_active=False
    )
    token = env.state.auth.create_email_verification_token(disabled.user_id)
    admin = env.browser(env.admin)
    turned_off = admin.put(
        f"/auth/users/{disabled.user_id}",
        data={"is_active": "false"},
        headers=admin.csrf_headers,
    )
    assert turned_off.status_code == 204

    anon = env.anonymous()
    csrf = _csrf(anon)
    with caplog.at_level(logging.INFO, logger="haris.auth.email"):
        disabled_page = anon.post(
            "/auth/resend-verification",
            data={"email": disabled.email, "csrf_token": csrf},
        )
        unknown_page = anon.post(
            "/auth/resend-verification",
            data={"email": "nobody@example.com", "csrf_token": csrf},
        )
    assert disabled_page.status_code == 200
    assert unknown_page.status_code == 200
    assert SUCCESS in disabled_page.text
    assert SUCCESS in unknown_page.text
    assert "verify-email" not in " ".join(record.message for record in caplog.records)
    assert env.state.auth.consume_email_verification_token(token) is None
    stored = env.state.auth.get_user_by_id(disabled.user_id)
    assert stored is not None
    assert stored.is_active is False
    assert stored.disabled_by_admin is True

    turned_on = admin.put(
        f"/auth/users/{disabled.user_id}",
        data={"is_active": "true"},
        headers=admin.csrf_headers,
    )
    assert turned_on.status_code == 204
    restored = env.state.auth.get_user_by_id(disabled.user_id)
    assert restored is not None
    assert restored.is_active is True
    assert restored.disabled_by_admin is False

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="haris.auth.email"):
        resent = anon.post(
            "/auth/resend-verification",
            data={"email": unverified.email, "csrf_token": csrf},
        )
    assert resent.status_code == 200
    match = VERIFY_URL.search(" ".join(record.message for record in caplog.records))
    assert match is not None
    activated = env.state.auth.consume_email_verification_token(match.group(1))
    assert activated is not None
    assert activated.is_active is True
    assert activated.disabled_by_admin is False


def test_m1_public_url_is_the_only_base_for_emailed_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("HARIS_PUBLIC_URL", "https://haris.example")
    env = WebEnv(tmp_path)
    user = env.state.auth.create_user(
        "new@techforpalestine.org", PASSWORD, is_active=False
    )
    anon = env.anonymous()
    csrf = _csrf(anon)
    with caplog.at_level(logging.INFO, logger="haris.auth.email"):
        response = anon.post(
            "/auth/resend-verification",
            data={"email": user.email, "csrf_token": csrf},
            headers={"host": "evil.test"},
        )
    assert response.status_code == 200
    logged = " ".join(record.message for record in caplog.records)
    assert "https://haris.example/auth/verify-email?token=" in logged
    assert "evil.test" not in logged
    assert "testserver" not in logged


def test_m1_unset_public_url_keeps_the_request_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("HARIS_PUBLIC_URL", raising=False)
    env = WebEnv(tmp_path)
    user = env.state.auth.create_user("new@example.com", PASSWORD, is_active=False)
    anon = env.anonymous()
    csrf = _csrf(anon)
    with caplog.at_level(logging.INFO, logger="haris.auth.email"):
        anon.post(
            "/auth/resend-verification",
            data={"email": user.email, "csrf_token": csrf},
        )
    logged = " ".join(record.message for record in caplog.records)
    assert "http://testserver/auth/verify-email?token=" in logged


def test_m1_allowed_hosts_rejects_unknown_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_ALLOWED_HOSTS", "haris.example")
    env = WebEnv(tmp_path, seed_users=False)
    anon = env.anonymous()
    anon.base_url = anon.base_url.copy_with(host="evil.test")
    assert anon.get("/login").status_code == 400
    anon.base_url = anon.base_url.copy_with(host="haris.example")
    assert anon.get("/login").status_code == 200


def _exhaust(client: Browser, path: str, data: dict[str, str], allowed: int) -> None:
    csrf = _csrf(client)
    body = {**data, "csrf_token": csrf}
    for _ in range(_LOGIN_MAX_ATTEMPTS):
        assert client.post(path, data=body).status_code == allowed
    assert client.post(path, data=body).status_code == 429


def test_m3_login_is_limited(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    _exhaust(
        env.anonymous(),
        "/login",
        {"email": "alice@example.com", "password": "wrong-password-1"},
        401,
    )


def test_m3_register_is_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_ALLOWED_EMAIL_DOMAINS", "techforpalestine.org")
    env = WebEnv(tmp_path, seed_users=False)
    _exhaust(
        env.anonymous(),
        "/auth/register",
        {
            "email": "ada@example.com",
            "password": PASSWORD,
            "display_name": "Ada",
        },
        403,
    )


def test_m3_resend_verification_is_limited(tmp_path: Path) -> None:
    env = WebEnv(tmp_path, seed_users=False)
    _exhaust(
        env.anonymous(),
        "/auth/resend-verification",
        {"email": "ada@example.com"},
        200,
    )


def test_l2_password_change_ends_other_sessions(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    client = env.browser(env.alice)
    other = env.state.auth.create_session(env.alice.user_id)
    current = client.cookies.get(SESSION_COOKIE)
    assert current
    response = client.post(
        "/auth/profile",
        data={
            "current_password": PASSWORD,
            "new_password": "correct-horse-battery-2",
            "csrf_token": _csrf(client, "/auth/profile"),
        },
    )
    assert response.status_code == 200
    assert "Profile updated." in response.text
    assert env.state.auth.get_session(str(current)) is not None
    assert env.state.auth.get_session(other.token) is None
    assert client.get("/auth/profile").status_code == 200


def test_l2_admin_deactivation_ends_all_sessions(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    session = env.state.auth.create_session(env.bob.user_id)
    admin = env.browser(env.admin)
    response = admin.put(
        f"/auth/users/{env.bob.user_id}",
        data={"is_active": "false"},
        headers=admin.csrf_headers,
    )
    assert response.status_code == 204
    assert env.state.auth.get_session(session.token) is None
    stored = env.state.auth.get_user_by_id(env.bob.user_id)
    assert stored is not None
    assert stored.is_active is False


def test_l3_cookie_secure_true_forces_secure_on_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_COOKIE_SECURE", "true")
    env = WebEnv(tmp_path)
    anon = env.anonymous()
    page = anon.get("/login")
    seed = page.headers["set-cookie"]
    assert seed.startswith(f"{SEED_COOKIE}=")
    assert "Secure" in seed
    # A Secure cookie is not stored for an http test client; put it back by hand.
    anon.cookies.set(SEED_COOKIE, seed.split(";", 1)[0].split("=", 1)[1])
    match = CSRF_FIELD.search(page.text)
    assert match is not None
    response = anon.post(
        "/login",
        data={
            "email": env.alice.email,
            "password": PASSWORD,
            "csrf_token": match.group(1),
        },
    )
    assert response.status_code == 303
    assert "Secure" in response.headers["set-cookie"]


def test_l3_cookie_secure_false_omits_secure_on_https(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_COOKIE_SECURE", "false")
    env = WebEnv(tmp_path)
    anon = env.anonymous()
    anon.base_url = anon.base_url.copy_with(scheme="https")
    csrf = _csrf(anon)
    response = anon.post(
        "/login",
        data={
            "email": env.alice.email,
            "password": PASSWORD,
            "csrf_token": csrf,
        },
    )
    assert response.status_code == 303
    assert "Secure" not in response.headers["set-cookie"]


def test_l5_new_scan_lists_own_shared_and_default_templates(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    own = ScanConfigTemplate(name="alice-only-template")
    private = ScanConfigTemplate(name="bob-only-template")
    default = ScanConfigTemplate(name="bob-default-template", is_default=True)
    shared = ScanConfigTemplate(name="shared-ownerless-template")
    env.state.store.save_scan_config_template(own, env.alice.user_id)
    env.state.store.save_scan_config_template(private, env.bob.user_id)
    env.state.store.save_scan_config_template(default, env.bob.user_id)
    env.state.store.save_scan_config_template(shared, "")
    page = env.browser(env.alice).get("/scan/new")
    assert page.status_code == 200
    assert "alice-only-template" in page.text
    assert "shared-ownerless-template" in page.text
    assert "bob-default-template" in page.text
    assert "Quick Surface Scan" in page.text
    assert "bob-only-template" not in page.text
    every = {row["name"] for row in env.state.store.list_scan_config_templates()}
    assert "bob-only-template" in every


def test_l7_setup_without_token_is_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HARIS_SETUP_TOKEN", raising=False)
    env = WebEnv(tmp_path, seed_users=False)
    anon = env.anonymous()
    assert anon.get("/auth/setup").status_code == 404
    response = anon.post(
        "/auth/setup",
        data={
            "email": "admin@example.com",
            "password": PASSWORD,
            "setup_token": "guessed",
            "csrf_token": _csrf(anon),
        },
    )
    assert response.status_code == 404
    assert env.state.auth.has_any_user() is False


def test_l7_setup_token_allows_one_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_SETUP_TOKEN", "setup-secret")
    env = WebEnv(tmp_path, seed_users=False)
    anon = env.anonymous()
    page = anon.get("/auth/setup")
    assert page.status_code == 200
    assert 'name="setup_token"' in page.text
    match = CSRF_FIELD.search(page.text)
    assert match is not None
    form = {
        "email": "admin@example.com",
        "password": PASSWORD,
        "csrf_token": match.group(1),
        "setup_token": "wrong",
    }
    assert anon.post("/auth/setup", data=form).status_code == 404
    form["setup_token"] = "setup-secret"
    created = anon.post("/auth/setup", data=form)
    assert created.status_code == 303
    assert anon.post("/auth/setup", data=form).status_code == 404
    users = env.state.auth.list_users()
    assert len(users) == 1
    assert users[0].is_admin is True
    assert users[0].role is UserRole.ADMIN
