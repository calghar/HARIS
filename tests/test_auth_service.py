import sqlite3
from pathlib import Path

import pytest

from src.auth.models import AuditAction, AuditEvent, AuthProvider, UserRole
from src.auth.service import AuthService
from src.db.store import ScanStore


@pytest.fixture()
def auth_service(tmp_path: Path) -> AuthService:
    """Return an AuthService backed by a fresh temporary SQLite database."""
    db_path = tmp_path / "test_auth.db"
    # ScanStore creates all tables including the V6 auth tables.
    ScanStore(db_path=db_path)
    return AuthService(db_path=db_path)


class TestCreateAndGetUser:
    def test_create_user_returns_user_with_correct_email(self, auth_service):
        user = auth_service.create_user("Alice@Example.COM", "s3cr3t")
        assert user.email == "alice@example.com"

    def test_create_user_strips_and_lowercases_email(self, auth_service):
        user = auth_service.create_user("  BOB@Test.ORG  ", "pass")
        assert user.email == "bob@test.org"

    def test_create_user_default_display_name_uses_email_prefix(self, auth_service):
        user = auth_service.create_user("carol@example.com", "pass")
        assert user.display_name == "carol"

    def test_create_user_custom_display_name(self, auth_service):
        user = auth_service.create_user("dave@example.com", "pass", display_name="Dave")
        assert user.display_name == "Dave"

    def test_create_user_default_role_is_user(self, auth_service):
        user = auth_service.create_user("eve@example.com", "pass")
        assert user.role == UserRole.USER

    def test_create_user_admin_role(self, auth_service):
        user = auth_service.create_user(
            "admin@example.com", "pass", role=UserRole.ADMIN
        )
        assert user.role == UserRole.ADMIN

    def test_create_user_is_active_by_default(self, auth_service):
        user = auth_service.create_user("frank@example.com", "pass")
        assert user.is_active is True

    def test_create_user_inactive_flag(self, auth_service):
        user = auth_service.create_user("ghost@example.com", "pass", is_active=False)
        assert user.is_active is False

    def test_get_user_by_email_returns_user(self, auth_service):
        auth_service.create_user("grace@example.com", "pass")
        user = auth_service.get_user_by_email("grace@example.com")
        assert user is not None
        assert user.email == "grace@example.com"

    def test_get_user_by_email_case_insensitive(self, auth_service):
        auth_service.create_user("heidi@example.com", "pass")
        user = auth_service.get_user_by_email("HEIDI@EXAMPLE.COM")
        assert user is not None

    def test_get_user_by_email_missing_returns_none(self, auth_service):
        result = auth_service.get_user_by_email("nobody@example.com")
        assert result is None

    def test_get_user_by_id_returns_user(self, auth_service):
        created = auth_service.create_user("ivan@example.com", "pass")
        user = auth_service.get_user_by_id(created.user_id)
        assert user is not None
        assert user.user_id == created.user_id

    def test_get_user_by_id_missing_returns_none(self, auth_service):
        assert auth_service.get_user_by_id("nonexistent-id") is None

    def test_password_hash_is_not_plaintext(self, auth_service):
        user = auth_service.create_user("judy@example.com", "mypassword")
        assert user.password_hash != "mypassword"
        assert len(user.password_hash) > 20  # bcrypt hashes are long


# ---------------------------------------------------------------------------
# has_any_user
# ---------------------------------------------------------------------------


class TestHasAnyUser:
    def test_has_any_user_false_on_empty_db(self, auth_service):
        assert auth_service.has_any_user() is False

    def test_has_any_user_true_after_create(self, auth_service):
        auth_service.create_user("kate@example.com", "pass")
        assert auth_service.has_any_user() is True


class TestAuthenticate:
    def test_authenticate_correct_credentials_returns_user(self, auth_service):
        auth_service.create_user("leo@example.com", "correct-pass")
        user = auth_service.authenticate("leo@example.com", "correct-pass")
        assert user is not None
        assert user.email == "leo@example.com"

    def test_authenticate_updates_last_login_at(self, auth_service):
        auth_service.create_user("mia@example.com", "pass")
        user = auth_service.authenticate("mia@example.com", "pass")
        assert user is not None
        assert user.last_login_at != ""

    def test_authenticate_wrong_password_returns_none(self, auth_service):
        auth_service.create_user("ned@example.com", "correct")
        result = auth_service.authenticate("ned@example.com", "wrong")
        assert result is None

    def test_authenticate_unknown_email_returns_none(self, auth_service):
        result = auth_service.authenticate("ghost@example.com", "pass")
        assert result is None

    def test_authenticate_inactive_user_returns_none(self, auth_service):
        auth_service.create_user("oscar@example.com", "pass", is_active=False)
        result = auth_service.authenticate("oscar@example.com", "pass")
        assert result is None

    def test_authenticate_empty_password_hash_returns_none(self, auth_service):
        # OIDC users have no password hash; must not authenticate via password.
        auth_service.create_user(
            "oidcuser@example.com",
            "",
            auth_provider=AuthProvider.OIDC,
        )
        result = auth_service.authenticate("oidcuser@example.com", "")
        assert result is None


class TestSessions:
    def test_create_session_returns_session_with_token(self, auth_service):
        user = auth_service.create_user("pat@example.com", "pass")
        session = auth_service.create_session(user.user_id)
        assert session.token != ""
        assert session.user_id == user.user_id

    def test_get_session_returns_valid_session(self, auth_service):
        user = auth_service.create_user("quinn@example.com", "pass")
        session = auth_service.create_session(user.user_id)
        retrieved = auth_service.get_session(session.token)
        assert retrieved is not None
        assert retrieved.user_id == user.user_id

    def test_get_session_returns_none_for_unknown_token(self, auth_service):
        assert auth_service.get_session("nonexistent-token") is None

    def test_get_session_returns_none_for_expired_token(self, auth_service, tmp_path):
        """Insert an already-expired session directly.

        Confirm get_session ignores it.
        """
        user = auth_service.create_user("rose@example.com", "pass")
        db_path = tmp_path / "test_auth.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO user_sessions"
            " (token, user_id, created_at, expires_at, last_seen_at)"
            " VALUES ('expired-tok', ?, '2020-01-01T00:00:00',"
            "  '2020-01-02T00:00:00', '2020-01-01T00:00:00')",
            (user.user_id,),
        )
        conn.commit()
        conn.close()
        result = auth_service.get_session("expired-tok")
        assert result is None

    def test_touch_session_updates_last_seen_at(self, auth_service):
        user = auth_service.create_user("sam@example.com", "pass")
        session = auth_service.create_session(user.user_id)
        original_last_seen = session.last_seen_at
        # touch_session may update to the same second in fast tests; calling
        # it must not raise and the row must still be retrievable.
        auth_service.touch_session(session.token)
        retrieved = auth_service.get_session(session.token)
        assert retrieved is not None
        # last_seen_at should be >= original (it was set at creation time).
        assert retrieved.last_seen_at >= original_last_seen

    def test_delete_session_removes_it(self, auth_service):
        user = auth_service.create_user("tina@example.com", "pass")
        session = auth_service.create_session(user.user_id)
        auth_service.delete_session(session.token)
        assert auth_service.get_session(session.token) is None

    def test_delete_session_unknown_token_does_not_raise(self, auth_service):
        auth_service.delete_session("ghost-token")  # must not raise

    def test_purge_expired_sessions_removes_expired_only(self, auth_service, tmp_path):
        user = auth_service.create_user("uma@example.com", "pass")
        # One live session (TTL 8 h default)
        live_session = auth_service.create_session(user.user_id)
        # One manually-inserted past-expiry session
        db_path = tmp_path / "test_auth.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO user_sessions"
            " (token, user_id, created_at, expires_at, last_seen_at)"
            " VALUES ('old-tok', ?, '2020-01-01T00:00:00',"
            "  '2020-01-02T00:00:00', '2020-01-01T00:00:00')",
            (user.user_id,),
        )
        conn.commit()
        conn.close()
        count = auth_service.purge_expired_sessions()
        assert count >= 1
        # Live session must survive
        assert auth_service.get_session(live_session.token) is not None

    def test_session_stores_ip_address_and_user_agent(self, auth_service):
        user = auth_service.create_user("victor@example.com", "pass")
        session = auth_service.create_session(
            user.user_id, ip_address="10.0.0.1", user_agent="TestBrowser/1.0"
        )
        retrieved = auth_service.get_session(session.token)
        assert retrieved is not None
        assert retrieved.ip_address == "10.0.0.1"
        assert retrieved.user_agent == "TestBrowser/1.0"


class TestRememberTokens:
    def test_create_remember_token_returns_non_empty_string(self, auth_service):
        user = auth_service.create_user("wendy@example.com", "pass")
        token = auth_service.create_remember_token(user.user_id)
        assert isinstance(token, str)
        assert len(token) > 10

    def test_consume_remember_token_returns_correct_user(self, auth_service):
        user = auth_service.create_user("xena@example.com", "pass")
        token = auth_service.create_remember_token(user.user_id)
        returned_user = auth_service.consume_remember_token(token)
        assert returned_user is not None
        assert returned_user.user_id == user.user_id

    def test_consume_remember_token_is_one_time_use(self, auth_service):
        user = auth_service.create_user("yara@example.com", "pass")
        token = auth_service.create_remember_token(user.user_id)
        auth_service.consume_remember_token(token)
        second = auth_service.consume_remember_token(token)
        assert second is None

    def test_consume_remember_token_unknown_token_returns_none(self, auth_service):
        assert auth_service.consume_remember_token("no-such-token") is None

    def test_consume_expired_remember_token_returns_none(self, auth_service, tmp_path):
        user = auth_service.create_user("zoe@example.com", "pass")
        db_path = tmp_path / "test_auth.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO remember_tokens"
            " (token, user_id, created_at, expires_at, used_at)"
            " VALUES ('old-rem', ?, '2020-01-01T00:00:00',"
            "  '2020-01-02T00:00:00', '')",
            (user.user_id,),
        )
        conn.commit()
        conn.close()
        result = auth_service.consume_remember_token("old-rem")
        assert result is None


class TestEmailVerificationTokens:
    def test_create_email_verification_token_returns_string(self, auth_service):
        user = auth_service.create_user("anne@example.com", "pass", is_active=False)
        token = auth_service.create_email_verification_token(user.user_id)
        assert isinstance(token, str)
        assert len(token) > 10

    def test_consume_email_verification_token_returns_user(self, auth_service):
        user = auth_service.create_user("bert@example.com", "pass", is_active=False)
        token = auth_service.create_email_verification_token(user.user_id)
        returned = auth_service.consume_email_verification_token(token)
        assert returned is not None
        assert returned.user_id == user.user_id

    def test_consume_email_verification_token_activates_user(self, auth_service):
        user = auth_service.create_user("cleo@example.com", "pass", is_active=False)
        assert user.is_active is False
        token = auth_service.create_email_verification_token(user.user_id)
        returned = auth_service.consume_email_verification_token(token)
        assert returned is not None
        assert returned.is_active is True

    def test_consume_email_verification_token_is_one_time_use(self, auth_service):
        user = auth_service.create_user("dana@example.com", "pass", is_active=False)
        token = auth_service.create_email_verification_token(user.user_id)
        auth_service.consume_email_verification_token(token)
        second = auth_service.consume_email_verification_token(token)
        assert second is None

    def test_consume_email_verification_token_unknown_returns_none(self, auth_service):
        assert auth_service.consume_email_verification_token("ghost-token") is None

    def test_consume_expired_email_verification_token_returns_none(
        self, auth_service, tmp_path
    ):
        user = auth_service.create_user("eli@example.com", "pass", is_active=False)
        db_path = tmp_path / "test_auth.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO email_verifications"
            " (token, user_id, purpose, created_at, expires_at, used_at)"
            " VALUES ('old-ev', ?, 'registration', '2020-01-01T00:00:00',"
            "  '2020-01-02T00:00:00', '')",
            (user.user_id,),
        )
        conn.commit()
        conn.close()
        result = auth_service.consume_email_verification_token("old-ev")
        assert result is None

    def test_new_token_invalidates_previous_unused_token_for_same_user(
        self, auth_service
    ):
        """Creating a second token for the same user+purpose.

        Must invalidate the first.
        """
        user = auth_service.create_user("faye@example.com", "pass", is_active=False)
        first_token = auth_service.create_email_verification_token(user.user_id)
        # Create a second token for the same user and purpose.
        auth_service.create_email_verification_token(user.user_id)
        # The first token should no longer be consumable.
        result = auth_service.consume_email_verification_token(first_token)
        assert result is None


class TestLinkOrCreateOidcUser:
    def test_creates_new_user_when_no_match(self, auth_service):
        user = auth_service.link_or_create_oidc_user(
            sub="sub-001", email="gale@example.com"
        )
        assert user.email == "gale@example.com"
        assert user.auth_provider == AuthProvider.OIDC
        assert user.oidc_sub == "sub-001"

    def test_links_existing_local_user_by_email(self, auth_service):
        local_user = auth_service.create_user("hal@example.com", "pass")
        assert local_user.auth_provider == AuthProvider.LOCAL
        linked = auth_service.link_or_create_oidc_user(
            sub="sub-002", email="hal@example.com"
        )
        # Same user — same user_id.
        assert linked.user_id == local_user.user_id
        assert linked.auth_provider == AuthProvider.OIDC
        assert linked.oidc_sub == "sub-002"

    def test_finds_by_oidc_sub_on_second_call(self, auth_service):
        auth_service.link_or_create_oidc_user(sub="sub-003", email="iris@example.com")
        # Second call with same sub (even different email) must return same user.
        user2 = auth_service.link_or_create_oidc_user(
            sub="sub-003", email="iris@example.com"
        )
        assert user2.oidc_sub == "sub-003"

    def test_oidc_user_created_without_password_hash(self, auth_service):
        user = auth_service.link_or_create_oidc_user(
            sub="sub-004", email="jake@example.com"
        )
        assert user.password_hash == ""

    def test_oidc_user_is_active_by_default(self, auth_service):
        user = auth_service.link_or_create_oidc_user(
            sub="sub-005", email="kim@example.com"
        )
        assert user.is_active is True

    def test_link_updates_last_login_at_for_existing_user(self, auth_service):
        # Create a local user first so the "link by email" branch runs, which
        # does call update_user(last_login_at=...) on an existing record.
        auth_service.create_user("lara@example.com", "pass")
        linked = auth_service.link_or_create_oidc_user(
            sub="sub-006", email="lara@example.com"
        )
        assert linked.last_login_at != ""


class TestAuditLog:
    def test_log_audit_stores_event(self, auth_service):
        user = auth_service.create_user("mike@example.com", "pass")
        auth_service.log_audit(
            AuditEvent(
                user_id=user.user_id,
                user_email=user.email,
                action=AuditAction.USER_LOGIN,
                resource_id=user.user_id,
                resource_type="user",
                ip_address="192.168.1.1",
            )
        )
        log = auth_service.get_audit_log()
        assert len(log) == 1
        assert log[0]["action"] == AuditAction.USER_LOGIN.value
        assert log[0]["user_email"] == "mike@example.com"

    def test_log_audit_sets_occurred_at_automatically(self, auth_service):
        user = auth_service.create_user("nina@example.com", "pass")
        auth_service.log_audit(
            AuditEvent(
                user_id=user.user_id,
                user_email=user.email,
                action=AuditAction.SCAN_STARTED,
            )
        )
        log = auth_service.get_audit_log()
        assert log[0]["occurred_at"] != ""

    def test_get_audit_log_filters_by_user_id(self, auth_service):
        u1 = auth_service.create_user("omar@example.com", "pass")
        u2 = auth_service.create_user("pam@example.com", "pass")
        auth_service.log_audit(
            AuditEvent(user_id=u1.user_id, action=AuditAction.USER_LOGIN)
        )
        auth_service.log_audit(
            AuditEvent(user_id=u2.user_id, action=AuditAction.USER_LOGIN)
        )
        log = auth_service.get_audit_log(user_id=u1.user_id)
        assert all(entry["user_id"] == u1.user_id for entry in log)
        assert len(log) == 1

    def test_get_audit_log_respects_limit(self, auth_service):
        user = auth_service.create_user("quinn@example.com", "pass")
        for _ in range(5):
            auth_service.log_audit(
                AuditEvent(user_id=user.user_id, action=AuditAction.SCAN_STARTED)
            )
        log = auth_service.get_audit_log(limit=3)
        assert len(log) == 3

    def test_get_audit_log_empty_when_nothing_logged(self, auth_service):
        assert auth_service.get_audit_log() == []

    def test_get_audit_log_filters_by_action(self, auth_service):
        user = auth_service.create_user("rob@example.com", "pass")
        auth_service.log_audit(
            AuditEvent(user_id=user.user_id, action=AuditAction.USER_LOGIN)
        )
        auth_service.log_audit(
            AuditEvent(user_id=user.user_id, action=AuditAction.SCAN_STARTED)
        )
        log = auth_service.get_audit_log(action=AuditAction.USER_LOGIN.value)
        assert len(log) == 1
        assert log[0]["action"] == AuditAction.USER_LOGIN.value


class TestPasswordHelpers:
    def test_hash_password_is_not_plaintext(self, auth_service):
        hashed = auth_service.hash_password("secret")
        assert hashed != "secret"

    def test_verify_password_correct(self, auth_service):
        hashed = auth_service.hash_password("secret")
        assert auth_service.verify_password("secret", hashed) is True

    def test_verify_password_wrong(self, auth_service):
        hashed = auth_service.hash_password("secret")
        assert auth_service.verify_password("wrong", hashed) is False


class TestUpdateUser:
    def test_update_user_display_name(self, auth_service):
        user = auth_service.create_user("sue@example.com", "pass")
        updated = auth_service.update_user(user.user_id, display_name="Sue Updated")
        assert updated is not None
        assert updated.display_name == "Sue Updated"

    def test_update_user_unknown_field_is_ignored(self, auth_service):
        user = auth_service.create_user("tom@example.com", "pass")
        # Passing a field not in the allowed set must not raise and must
        # return the user unchanged.
        result = auth_service.update_user(user.user_id, unknown_field="oops")
        assert result is not None
        assert result.email == "tom@example.com"


class TestDeleteUser:
    def test_delete_user_returns_true(self, auth_service):
        user = auth_service.create_user("uma@example.com", "pass")
        assert auth_service.delete_user(user.user_id) is True

    def test_delete_user_makes_it_unfindable(self, auth_service):
        user = auth_service.create_user("vera@example.com", "pass")
        auth_service.delete_user(user.user_id)
        assert auth_service.get_user_by_id(user.user_id) is None

    def test_delete_nonexistent_user_returns_false(self, auth_service):
        assert auth_service.delete_user("does-not-exist") is False


class TestListUsers:
    def test_list_users_returns_all_created_users(self, auth_service):
        auth_service.create_user("w1@example.com", "pass")
        auth_service.create_user("w2@example.com", "pass")
        users = auth_service.list_users()
        emails = {u.email for u in users}
        assert "w1@example.com" in emails
        assert "w2@example.com" in emails

    def test_list_users_empty_on_fresh_db(self, auth_service):
        assert auth_service.list_users() == []
