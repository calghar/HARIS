from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from haris.auth.cookies import SESSION_COOKIE
from haris.auth.models import AuthProvider, UserRole
from haris.auth.oidc import OIDCClient, OIDCConfig

from .test_web_env import WebEnv

CONFIG = OIDCConfig(enabled=True, issuer="https://idp.example.test", client_id="haris")


class FakeIdP(OIDCClient):
    """Real claim handling; the token exchange returns canned userinfo."""

    userinfo: dict[str, Any] = {}
    fail = False

    async def handle_callback(self, request: Request) -> dict[str, Any]:
        if self.fail:
            raise RuntimeError("token exchange failed")
        return dict(self.userinfo)


@pytest.fixture()
def idp(monkeypatch: pytest.MonkeyPatch) -> FakeIdP:
    client = FakeIdP(CONFIG)
    monkeypatch.setattr("haris.web.routers.oidc.get_oidc_client", lambda: client)
    return client


@pytest.fixture()
def env(tmp_path: Path) -> Iterator[WebEnv]:
    yield WebEnv(tmp_path)


def claims(**extra: Any) -> dict[str, Any]:
    return {
        "sub": "idp-1",
        "email": "new@example.com",
        "email_verified": True,
        **extra,
    }


class TestExtractRole:
    @pytest.mark.parametrize(
        ("userinfo", "role"),
        [
            ({"haris_role": "haris-admin"}, UserRole.ADMIN),
            ({"haris_role": ["x", "haris-admin"]}, UserRole.ADMIN),
            ({"realm_access": {"roles": ["haris-admin"]}}, UserRole.ADMIN),
            ({"haris_role": "viewer"}, UserRole.USER),
            ({"haris_role": "xharis-adminx"}, UserRole.USER),
            ({"haris_role": None}, UserRole.USER),
            ({"haris_role": 7}, UserRole.USER),
            ({"realm_access": "haris-admin"}, UserRole.USER),
            ({"realm_access": {"roles": "haris-admin"}}, UserRole.ADMIN),
            ({"realm_access": {}}, UserRole.USER),
            ({}, UserRole.USER),
        ],
    )
    def test_role_mapping(self, userinfo: dict[str, Any], role: UserRole) -> None:
        assert OIDCClient(CONFIG).extract_role(userinfo) is role


class TestEmailVerified:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, True),
            ("true", True),
            (False, False),
            ("false", False),
            ("yes", False),
            (1, False),
            (None, False),
        ],
    )
    def test_claim_values(self, value: Any, expected: bool) -> None:
        assert OIDCClient.is_email_verified({"email_verified": value}) is expected

    def test_missing_claim_is_unverified(self) -> None:
        assert OIDCClient.is_email_verified({}) is False


class TestCallback:
    def test_verified_new_user_is_created_and_logged_in(
        self, env: WebEnv, idp: FakeIdP
    ) -> None:
        idp.userinfo = claims()
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.status_code == 303
        assert response.headers["location"] == "/"
        assert SESSION_COOKIE in response.headers["set-cookie"]
        user = env.state.auth.get_user_by_email("new@example.com")
        assert user is not None
        assert user.auth_provider is AuthProvider.OIDC
        assert user.role is UserRole.USER

    def test_admin_claim_creates_admin(self, env: WebEnv, idp: FakeIdP) -> None:
        idp.userinfo = claims(haris_role="haris-admin")
        env.anonymous().get("/auth/oidc/callback")
        user = env.state.auth.get_user_by_email("new@example.com")
        assert user is not None
        assert user.role is UserRole.ADMIN

    def test_unverified_email_is_denied(self, env: WebEnv, idp: FakeIdP) -> None:
        idp.userinfo = claims(email_verified=False)
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.headers["location"] == "/login?error=oidc_denied"
        assert SESSION_COOKIE not in response.headers.get("set-cookie", "")
        assert env.state.auth.get_user_by_email("new@example.com") is None

    def test_unverified_email_does_not_take_over_local_account(
        self, env: WebEnv, idp: FakeIdP
    ) -> None:
        idp.userinfo = claims(email=env.alice.email, email_verified=False)
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.headers["location"] == "/login?error=oidc_denied"
        stored = env.state.auth.get_user_by_id(env.alice.user_id)
        assert stored is not None
        assert stored.auth_provider is AuthProvider.LOCAL
        assert stored.oidc_sub == ""

    def test_verified_email_links_active_local_account(
        self, env: WebEnv, idp: FakeIdP
    ) -> None:
        idp.userinfo = claims(email=env.alice.email, haris_role="haris-admin")
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.headers["location"] == "/"
        stored = env.state.auth.get_user_by_id(env.alice.user_id)
        assert stored is not None
        assert stored.oidc_sub == "idp-1"
        assert stored.role is UserRole.USER  # a claim never promotes a linked account

    def test_inactive_account_is_denied(self, env: WebEnv, idp: FakeIdP) -> None:
        env.state.auth.update_user(env.bob.user_id, is_active=False)
        idp.userinfo = claims(email=env.bob.email)
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.headers["location"] == "/login?error=oidc_denied"

    def test_token_exchange_failure_is_reported(
        self, env: WebEnv, idp: FakeIdP
    ) -> None:
        idp.fail = True
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.headers["location"] == "/login?error=oidc_error"

    @pytest.mark.parametrize("missing", ["sub", "email"])
    def test_missing_claims_are_reported(
        self, env: WebEnv, idp: FakeIdP, missing: str
    ) -> None:
        idp.userinfo = {k: v for k, v in claims().items() if k != missing}
        response = env.anonymous().get("/auth/oidc/callback")
        assert response.headers["location"] == "/login?error=oidc_missing_claims"

    def test_disabled_oidc_returns_404(self, env: WebEnv) -> None:
        assert env.anonymous().get("/auth/oidc/callback").status_code == 404
        assert env.anonymous().get("/auth/oidc/login").status_code == 404

    @pytest.mark.parametrize(
        ("code", "text"),
        [
            ("oidc_denied", "refused"),
            ("oidc_error", "Single sign-on failed"),
            ("oidc_missing_claims", "did not return an email"),
        ],
    )
    def test_login_page_explains_error_code(
        self, env: WebEnv, code: str, text: str
    ) -> None:
        page = env.anonymous().get("/login", params={"error": code})
        assert text in page.text

    def test_unknown_error_code_is_not_reflected(self, env: WebEnv) -> None:
        page = env.anonymous().get("/login", params={"error": "<b>pwn</b>"})
        assert "<b>pwn</b>" not in page.text
