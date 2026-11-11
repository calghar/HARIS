import secrets

from .database import future_iso, now_iso
from .models import User
from .tokens import hash_token
from .users import UserStore

REGISTRATION_PURPOSE = "registration"


class VerificationTokens(UserStore):
    def create_remember_token(self, user_id: str, *, ttl_days: int = 30) -> str:
        token = secrets.token_urlsafe(48)
        now = now_iso()
        expires = future_iso(days=ttl_days)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO remember_tokens (token, user_id, created_at, expires_at,\
                      used_at) VALUES (?,?,?,?,?)",
                (hash_token(token), user_id, now, expires, ""),
            )
        return token

    def consume_remember_token(self, token: str) -> User | None:
        """One-time use. Marks token as used and returns the associated user."""
        now = now_iso()
        token_hash = hash_token(token)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remember_tokens WHERE token = ?"
                " AND expires_at > ? AND used_at = ''",
                (token_hash, now),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE remember_tokens SET used_at = ? WHERE token = ?",
                (now, token_hash),
            )
        return self.get_user_by_id(row["user_id"])

    def create_email_verification_token(
        self, user_id: str, purpose: str = REGISTRATION_PURPOSE, *, ttl_hours: int = 24
    ) -> str:
        token = secrets.token_urlsafe(32)
        now = now_iso()
        expires = future_iso(hours=ttl_hours)
        with self._connect() as conn:
            # Invalidate previous unused tokens for same user+purpose
            conn.execute(
                "DELETE FROM email_verifications WHERE user_id = ?\
                      AND purpose = ? AND used_at = ''",
                (user_id, purpose),
            )
            conn.execute(
                """
                INSERT INTO email_verifications
                    (token, user_id, purpose, created_at, expires_at, used_at)
                VALUES (?,?,?,?,?,'')
                """,
                (hash_token(token), user_id, purpose, now, expires),
            )
        return token

    def consume_email_verification_token(self, token: str) -> User | None:
        """Registration activates a user an admin did not disable."""
        now = now_iso()
        token_hash = hash_token(token)
        user_id = ""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM email_verifications WHERE token = ? AND expires_at"
                " > ? AND used_at = ''",
                (token_hash, now),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE email_verifications SET used_at = ? WHERE token = ?",
                (now, token_hash),
            )
            user_row = conn.execute(
                "SELECT disabled_by_admin FROM users WHERE user_id = ?",
                (row["user_id"],),
            ).fetchone()
            disabled = user_row is None or bool(user_row["disabled_by_admin"])
            if row["purpose"] != REGISTRATION_PURPOSE or disabled:
                return None
            conn.execute(
                "UPDATE users SET is_active = 1, updated_at = ? WHERE user_id = ?",
                (now, row["user_id"]),
            )
            user_id = str(row["user_id"])
        return self.get_user_by_id(user_id)
