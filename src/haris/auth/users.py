import sqlite3
from typing import Any

import bcrypt as _bcrypt_lib

from .audit import AuditLog
from .database import now_iso
from .models import AuthProvider, User, UserRole

_UPDATABLE_FIELDS = {
    "display_name",
    "role",
    "is_active",
    "disabled_by_admin",
    "password_hash",
    "last_login_at",
}


class UserStore(AuditLog):
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
        now = now_iso()
        user = self._build_user(
            email,
            password,
            display_name,
            role,
            is_active=is_active,
            auth_provider=auth_provider,
            oidc_sub=oidc_sub,
            now=now,
        )
        with self._connect() as conn:
            self._insert_user(conn, user)
        return user

    def _build_user(
        self,
        email: str,
        password: str,
        display_name: str,
        role: UserRole,
        *,
        is_active: bool,
        auth_provider: AuthProvider,
        oidc_sub: str,
        now: str,
    ) -> User:
        return User(
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

    @staticmethod
    def _insert_user(conn: sqlite3.Connection, user: User) -> None:
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
        updates = {k: v for k, v in fields.items() if k in _UPDATABLE_FIELDS}
        if not updates:
            return self.get_user_by_id(user_id)
        updates["updated_at"] = now_iso()
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
            disabled_by_admin=bool(row["disabled_by_admin"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login_at=row["last_login_at"],
        )
