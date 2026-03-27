import logging
import os

from .models import AuditAction, AuditEvent, UserRole
from .service import AuthService

logger = logging.getLogger(__name__)


def bootstrap_admin_from_env(auth_service: AuthService) -> None:
    """Create the initial admin user from environment variables.

    Only runs when HARIS_ADMIN_EMAIL and HARIS_ADMIN_PASSWORD are set
    AND no users exist yet. Safe to call on every startup.
    """
    email = os.environ.get("HARIS_ADMIN_EMAIL", "").strip()
    password = os.environ.get("HARIS_ADMIN_PASSWORD", "").strip()
    if not email or not password:
        return
    if auth_service.has_any_user():
        logger.debug("Admin bootstrap skipped: users already exist")
        return
    user = auth_service.create_user(
        email=email,
        password=password,
        display_name="Administrator",
        role=UserRole.ADMIN,
        is_active=True,
    )
    logger.info("Bootstrap: created admin user %s", user.email)
    auth_service.log_audit(
        AuditEvent(
            user_email="system",
            action=AuditAction.USER_CREATED,
            resource_id=user.user_id,
            resource_type="user",
            details={"reason": "env_bootstrap", "role": "admin"},
        )
    )
