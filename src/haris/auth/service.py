import logging
import secrets
from typing import Any

import bcrypt as _bcrypt_lib

from .database import future_iso, now_iso
from .models import AuthProvider, User, UserRole, UserSession
from .tokens import hash_token
from .verification import VerificationTokens

logger = logging.getLogger(__name__)


class AuthService(VerificationTokens):
    def hash_password(self, plain: str) -> str:
        return _bcrypt_lib.hashpw(plain.encode(), _bcrypt_lib.gensalt()).decode()

    def verify_password(self, plain: str, hashed: str) -> bool:
        return _bcrypt_lib.checkpw(plain.encode(), hashed.encode())

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.get_user_by_email(email)
        if user is None or not user.is_active:
            return None
        if not user.password_hash or not self.verify_password(
            password, user.password_hash
        ):
            return None
        self.update_user(user.user_id, last_login_at=now_iso())
        return self.get_user_by_id(user.user_id)

    def create_session(
        self,
        user_id: str,
        ip_address: str = "",
        user_agent: str = "",
        *,
        ttl_hours: int = 8,
    ) -> UserSession:
        token = secrets.token_urlsafe(32)
        now = now_iso()
        expires = future_iso(hours=ttl_hours)
        session = UserSession(
            token=token,
            token_hash=hash_token(token),
            user_id=user_id,
            created_at=now,
            expires_at=expires,
            last_seen_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO user_sessions
                    (token, user_id, created_at, expires_at,
                    last_seen_at, ip_address, user_agent)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    session.token_hash,
                    user_id,
                    now,
                    expires,
                    now,
                    ip_address,
                    user_agent,
                ),
            )
        return session

    def get_session(self, token: str) -> UserSession | None:
        now = now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM user_sessions WHERE token = ? AND expires_at > ?",
                (hash_token(token), now),
            ).fetchone()
        if not row:
            return None
        return UserSession(
            token_hash=row["token"],
            user_id=row["user_id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            last_seen_at=row["last_seen_at"],
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
        )

    def touch_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE user_sessions SET last_seen_at = ? WHERE token = ?",
                (now_iso(), hash_token(token)),
            )

    def delete_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM user_sessions WHERE token = ?", (hash_token(token),)
            )

    def list_user_sessions(
        self, user_id: str, current_token: str
    ) -> list[dict[str, Any]]:
        current_hash = hash_token(current_token)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM user_sessions WHERE user_id = ? "
                "ORDER BY last_seen_at DESC",
                (user_id,),
            ).fetchall()
        return [
            {
                **dict(r),
                "token_hash": r["token"],
                "is_current": r["token"] == current_hash,
            }
            for r in rows
        ]

    def revoke_session_by_hash(self, user_id: str, token_hash: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM user_sessions WHERE token = ? AND user_id = ?",
                (token_hash, user_id),
            )
        return cur.rowcount > 0

    def delete_all_user_sessions(self, user_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))

    def purge_expired_sessions(self) -> int:
        now = now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM user_sessions WHERE expires_at <= ?", (now,)
            )
            # Also purge expired remember tokens and email verifications
            conn.execute("DELETE FROM remember_tokens WHERE expires_at <= ?", (now,))
            conn.execute(
                "DELETE FROM email_verifications\
                      WHERE expires_at <= ? AND used_at = ''",
                (now,),
            )
        return cur.rowcount

    def link_or_create_oidc_user(
        self,
        sub: str,
        email: str,
        display_name: str = "",
        *,
        email_verified: bool = False,
        role: UserRole = UserRole.USER,
    ) -> User | None:
        """Resolve an OIDC identity to an active user, or None to deny login.

        Known `sub` logs in; linking or creating by email needs a verified email.
        """
        email = email.strip().lower()
        user = self.get_user_by_oidc_sub(sub)
        if user is None:
            if not email_verified:
                logger.warning("OIDC login refused: email %s not verified", email)
                return None
            user = self.get_user_by_email(email)
            if user is None:
                return self.create_user(
                    email=email,
                    password="",
                    display_name=display_name or email.split("@")[0],
                    role=role,
                    is_active=True,
                    auth_provider=AuthProvider.OIDC,
                    oidc_sub=sub,
                )
            if user.oidc_sub or not user.is_active:
                logger.warning("OIDC link refused for %s", user.user_id)
                return None
            self._bind_oidc_sub(user.user_id, sub)
        if not user.is_active:
            logger.warning("OIDC login refused: user %s is inactive", user.user_id)
            return None
        return self.update_user(user.user_id, last_login_at=now_iso())

    def _bind_oidc_sub(self, user_id: str, sub: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET oidc_sub = ?, auth_provider = ?, updated_at = ?"
                " WHERE user_id = ?",
                (sub, AuthProvider.OIDC.value, now_iso(), user_id),
            )
