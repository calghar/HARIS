import enum
import uuid
from typing import Any

from pydantic import BaseModel, Field


class UserRole(enum.Enum):
    ADMIN = "admin"
    USER = "user"


class AuthProvider(enum.Enum):
    LOCAL = "local"
    OIDC = "oidc"


class AuditAction(enum.Enum):
    SCAN_STARTED = "scan.started"
    SCAN_DELETED = "scan.deleted"
    TEMPLATE_CREATED = "template.created"
    TEMPLATE_UPDATED = "template.updated"
    TEMPLATE_DELETED = "template.deleted"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_REGISTERED = "user.registered"
    USER_ACTIVATED = "user.activated"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_LOGOUT = "user.logout"


class User(BaseModel):
    user_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    email: str
    display_name: str = ""
    password_hash: str = ""
    role: UserRole = UserRole.USER
    auth_provider: AuthProvider = AuthProvider.LOCAL
    oidc_sub: str = ""
    is_active: bool = True
    created_at: str = ""
    updated_at: str = ""
    last_login_at: str = ""


class UserPublic(BaseModel):
    """Safe user representation — never includes password_hash."""

    user_id: str
    email: str
    display_name: str
    role: UserRole
    auth_provider: AuthProvider
    is_active: bool
    created_at: str
    last_login_at: str

    @classmethod
    def from_user(cls, user: User) -> "UserPublic":
        return cls(
            user_id=user.user_id,
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            auth_provider=user.auth_provider,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )


class UserSession(BaseModel):
    token: str
    user_id: str
    created_at: str
    expires_at: str
    last_seen_at: str
    ip_address: str = ""
    user_agent: str = ""


class AuditEvent(BaseModel):
    user_id: str = ""
    user_email: str = ""
    action: AuditAction
    resource_id: str = ""
    resource_type: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    ip_address: str = ""
    occurred_at: str = ""
