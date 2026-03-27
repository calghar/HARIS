import json
import logging
import secrets
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import bcrypt as _bcrypt_lib

from .models import AuditEvent, AuthProvider, User, UserRole, UserSession

logger = logging.getLogger(__name__)

_SCHEMA_INIT_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _future_iso(*, hours: int = 0, days: int = 0) -> str:
    delta = timedelta(hours=hours, days=days)
    return (datetime.now(UTC) + delta).isoformat(timespec="seconds")


class AuthService:
    def __init__(self, db_path: str | Path = "data/HARIS.db") -> None:
        self._db_path = Path(db_path)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA_INIT_SQL)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_user(
        self,
        email: str,
        password: str,
        display_name: str = "",
        role: UserRole = UserRole.USER,
        *,
        is_active: bool = True,
        auth_provider: AuthProvider = AuthProvider.LOCAL,
        oidc_sub: str = "",
    ) -> User:
        email = email.strip().lower()
        now = _now_iso()
        user = User(
            email=email,
            display_name=display_name or email.split("@")[0],
            password_hash=(
                _bcrypt_lib.hashpw(password.encode(), _bcrypt_lib.gensalt()).decode()
                if password
                else ""
            ),
            role=role,
            auth_provider=auth_provider,
            oidc_sub=oidc_sub,
            is_active=is_active,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (user_id, email, display_name, password_hash, role, auth_provider,
                     oidc_sub, is_active, created_at, updated_at, last_login_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,'')
                """,
                (
                    user.user_id,
                    user.email,
                    user.display_name,
                    user.password_hash,
                    user.role.value,
                    user.auth_provider.value,
                    user.oidc_sub,
                    int(user.is_active),
                    user.created_at,
                    user.updated_at,
                ),
            )
        return user

    def get_user_by_email(self, email: str) -> User | None:
        email = email.strip().lower()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_id(self, user_id: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_oidc_sub(self, sub: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE oidc_sub = ?", (sub,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[User]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_user(r) for r in rows]

    def update_user(self, user_id: str, **fields: Any) -> User | None:
        allowed = {
            "display_name",
            "role",
            "is_active",
            "password_hash",
            "last_login_at",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_user_by_id(user_id)
        updates["updated_at"] = _now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [user_id]
        with self._connect() as conn:
            conn.execute(
                f"UPDATE users SET {set_clause} WHERE user_id = ?",  # nosec B608
                values,
            )
        return self.get_user_by_id(user_id)

    def delete_user(self, user_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        return cur.rowcount > 0

    def has_any_user(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return row is not None

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
        self.update_user(user.user_id, last_login_at=_now_iso())
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
        now = _now_iso()
        expires = _future_iso(hours=ttl_hours)
        session = UserSession(
            token=token,
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
                (token, user_id, now, expires, now, ip_address, user_agent),
            )
        return session

    def get_session(self, token: str) -> UserSession | None:
        now = _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM user_sessions WHERE token = ? AND expires_at > ?",
                (token, now),
            ).fetchone()
        if not row:
            return None
        return UserSession(
            token=row["token"],
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
                (_now_iso(), token),
            )

    def delete_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))

    def delete_all_user_sessions(self, user_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))

    def purge_expired_sessions(self) -> int:
        now = _now_iso()
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

    def create_remember_token(self, user_id: str, *, ttl_days: int = 30) -> str:
        token = secrets.token_urlsafe(48)
        now = _now_iso()
        expires = _future_iso(days=ttl_days)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO remember_tokens (token, user_id, created_at, expires_at,\
                      used_at) VALUES (?,?,?,?,?)",
                (token, user_id, now, expires, ""),
            )
        return token

    def consume_remember_token(self, token: str) -> User | None:
        """One-time use. Marks token as used and returns the associated user."""
        now = _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remember_tokens WHERE token = ?"
                " AND expires_at > ? AND used_at = ''",
                (token, now),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE remember_tokens SET used_at = ? WHERE token = ?",
                (now, token),
            )
        return self.get_user_by_id(row["user_id"])

    def create_email_verification_token(
        self, user_id: str, purpose: str = "registration", *, ttl_hours: int = 24
    ) -> str:
        token = secrets.token_urlsafe(32)
        now = _now_iso()
        expires = _future_iso(hours=ttl_hours)
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
                (token, user_id, purpose, now, expires),
            )
        return token

    def consume_email_verification_token(self, token: str) -> User | None:
        """Marks the token as used, activates the user, returns the user
        or None if invalid."""
        now = _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM email_verifications WHERE token = ? AND expires_at"
                " > ? AND used_at = ''",
                (token, now),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE email_verifications SET used_at = ? WHERE token = ?",
                (now, token),
            )
            conn.execute(
                "UPDATE users SET is_active = 1, updated_at = ? WHERE user_id = ?",
                (now, row["user_id"]),
            )
        return self.get_user_by_id(row["user_id"])

    def link_or_create_oidc_user(
        self, sub: str, email: str, display_name: str = ""
    ) -> User:
        """Find user by OIDC sub, then by email (linking), then create new."""
        email = email.strip().lower()
        # Try by sub first
        user = self.get_user_by_oidc_sub(sub)
        if user:
            self.update_user(user.user_id, last_login_at=_now_iso())
            return self.get_user_by_id(user.user_id)  # type: ignore[return-value]
        # Try to link by email (existing local account)
        user = self.get_user_by_email(email)
        if user:
            self.update_user(user.user_id, last_login_at=_now_iso())
            with self._connect() as conn:
                conn.execute(
                    "UPDATE users SET oidc_sub = ?, auth_provider = ?,\
                          updated_at = ? WHERE user_id = ?",
                    (sub, AuthProvider.OIDC.value, _now_iso(), user.user_id),
                )
            return self.get_user_by_id(user.user_id)  # type: ignore[return-value]
        # Create new OIDC user
        return self.create_user(
            email=email,
            password="",
            display_name=display_name or email.split("@")[0],
            role=UserRole.USER,
            is_active=True,
            auth_provider=AuthProvider.OIDC,
            oidc_sub=sub,
        )

    def log_audit(self, event: AuditEvent) -> None:
        if not event.occurred_at:
            event = event.model_copy(update={"occurred_at": _now_iso()})
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (user_id, user_email, action, resource_id, resource_type,
                     details_json, ip_address, occurred_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    event.user_id,
                    event.user_email,
                    event.action.value,
                    event.resource_id,
                    event.resource_type,
                    json.dumps(event.details),
                    event.ip_address,
                    event.occurred_at,
                ),
            )

    def get_audit_log(
        self,
        limit: int = 100,
        *,
        user_id: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if action:
            conditions.append("action = ?")
            params.append(action)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_log {where} ORDER BY occurred_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Internal helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        return User(
            user_id=row["user_id"],
            email=row["email"],
            display_name=row["display_name"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            auth_provider=AuthProvider(row["auth_provider"]),
            oidc_sub=row["oidc_sub"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login_at=row["last_login_at"],
        )
