import time
from email import message_from_string
from email.message import Message
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from haris.auth.email import EmailSender, SMTPConfig
from haris.auth.middleware import (
    _LOGIN_MAX_ATTEMPTS,
    _LOGIN_WINDOW_SECONDS,
    check_rate_limit,
)
from haris.auth.service import AuthService
from haris.db.connection import connect
from haris.db.store import ScanStore


@pytest.fixture()
def auth_service(tmp_path: Path) -> AuthService:
    db_path = tmp_path / "auth.db"
    ScanStore(db_path)
    return AuthService(db_path)


def test_h1_existing_rows_default_not_disabled(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    ScanStore(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (user_id, email, created_at, updated_at)"
            " VALUES ('u1', 'old@example.com', '', '')"
        )

    user = AuthService(db_path).get_user_by_id("u1")

    assert user is not None
    assert user.disabled_by_admin is False


def test_h1_consume_activates_only_registration_purpose(
    auth_service: AuthService,
) -> None:
    user = auth_service.create_user("ada@example.com", "correct-horse", is_active=False)
    reset = auth_service.create_email_verification_token(user.user_id, "reset")

    assert auth_service.consume_email_verification_token(reset) is None
    stored = auth_service.get_user_by_id(user.user_id)
    assert stored is not None
    assert stored.is_active is False

    registration = auth_service.create_email_verification_token(user.user_id)
    activated = auth_service.consume_email_verification_token(registration)
    assert activated is not None
    assert activated.is_active is True


def test_l1_unknown_and_inactive_users_still_check_password(
    auth_service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth_service.create_user("idle@example.com", "correct-horse", is_active=False)
    checked: list[str] = []
    real = auth_service.verify_password

    def spy(plain: str, hashed: str) -> bool:
        checked.append(hashed)
        return real(plain, hashed)

    monkeypatch.setattr(auth_service, "verify_password", spy)

    assert auth_service.authenticate("nobody@example.com", "guess") is None
    assert auth_service.authenticate("idle@example.com", "guess") is None
    assert len(checked) == 2


def test_m3_account_limit_follows_the_email_across_ips_and_stays_in_the_db(
    tmp_path: Path,
) -> None:
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    ScanStore(db_a)
    ScanStore(db_b)
    auth_a = AuthService(db_a)
    for _ in range(_LOGIN_MAX_ATTEMPTS):
        check_rate_limit(auth_a, "203.0.113.1", "Alice@Example.com")

    with pytest.raises(HTTPException) as blocked:
        check_rate_limit(AuthService(db_a), "203.0.113.9", "alice@example.com")
    assert blocked.value.status_code == 429
    check_rate_limit(AuthService(db_b), "203.0.113.1", "alice@example.com")


def test_m3_attempt_window_expires(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.db"
    ScanStore(db_path)
    auth = AuthService(db_path)
    check_rate_limit(auth, "203.0.113.4", "ada@example.com")
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE auth_attempt_counters SET attempts = ?, window_started = ?",
            (_LOGIN_MAX_ATTEMPTS, time.time() - _LOGIN_WINDOW_SECONDS - 1),
        )

    check_rate_limit(auth, "203.0.113.4", "ada@example.com")


def test_m4_oidc_create_rejects_a_disallowed_domain(
    auth_service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARIS_ALLOWED_EMAIL_DOMAINS", "techforpalestine.org")
    assert (
        auth_service.link_or_create_oidc_user(
            sub="sub-out", email="person@evil.test", email_verified=True
        )
        is None
    )
    assert auth_service.get_user_by_email("person@evil.test") is None
    created = auth_service.link_or_create_oidc_user(
        sub="sub-in", email="person@techforpalestine.org", email_verified=True
    )
    assert created is not None
    assert created.is_active is True

    local = auth_service.create_user("local@evil.test", "correct-horse")
    linked = auth_service.link_or_create_oidc_user(
        sub="sub-link", email=local.email, email_verified=True
    )
    assert linked is not None
    assert linked.user_id == local.user_id

    monkeypatch.setenv("HARIS_ALLOWED_EMAIL_DOMAINS", "")
    opened = auth_service.link_or_create_oidc_user(
        sub="sub-any", email="person@anywhere.test", email_verified=True
    )
    assert opened is not None


def test_l7_bootstrap_row_blocks_a_second_admin(auth_service: AuthService) -> None:
    first = auth_service.create_initial_admin("a@example.com", "correct-horse-battery")
    assert first is not None
    assert first.role.value == "admin"
    assert (
        auth_service.create_initial_admin("b@example.com", "correct-horse-battery")
        is None
    )
    assert auth_service.get_user_by_email("b@example.com") is None

    with connect(auth_service._db_path) as conn:
        conn.execute("DELETE FROM users")
    assert (
        auth_service.create_initial_admin("c@example.com", "correct-horse-battery")
        is None
    )
    assert auth_service.has_any_user() is False


def test_m1_html_mail_escapes_the_url() -> None:
    sender = EmailSender(SMTPConfig(enabled=True, use_tls=False))
    smtp = MagicMock()
    smtp.__enter__ = MagicMock(return_value=smtp)
    smtp.__exit__ = MagicMock(return_value=False)
    with patch("haris.auth.email.smtplib.SMTP", return_value=smtp):
        sender.send_verification_email(
            to_email="ada@example.com",
            token='"><script>alert(1)</script>',
            base_url="https://haris.example",
        )

    raw = smtp.sendmail.call_args.args[2]
    parts = message_from_string(raw).get_payload()
    assert isinstance(parts, list)
    html_part = parts[1]
    assert isinstance(html_part, Message)
    html = html_part.get_payload(decode=True)
    assert isinstance(html, bytes)
    body = html.decode()
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert "&quot;" in body
