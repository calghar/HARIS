import os

from .email import EmailSender, SMTPConfig
from .oidc import OIDCClient, OIDCConfig

TRUE_VALUES = {"1", "true", "yes"}
MIN_PASSWORD_LENGTH = 12

_oidc_client: OIDCClient | None = None


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in TRUE_VALUES


def get_oidc_client() -> OIDCClient:
    global _oidc_client
    if _oidc_client is None:
        config = OIDCConfig(
            enabled=env_flag("HARIS_OIDC_ENABLED"),
            issuer=os.environ.get("HARIS_OIDC_ISSUER", ""),
            client_id=os.environ.get("HARIS_OIDC_CLIENT_ID", ""),
            client_secret=os.environ.get("HARIS_OIDC_CLIENT_SECRET", ""),
        )
        _oidc_client = OIDCClient(config)
    return _oidc_client


def get_allowed_domains() -> list[str]:
    """Return configured allowed email domains. Empty list = allow all."""
    raw = os.environ.get("HARIS_ALLOWED_EMAIL_DOMAINS", "techforpalestine.org")
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def get_email_sender() -> EmailSender:
    config = SMTPConfig(
        enabled=env_flag("HARIS_SMTP_ENABLED"),
        host=os.environ.get("HARIS_SMTP_HOST", "localhost"),
        port=int(os.environ.get("HARIS_SMTP_PORT", "587")),
        username=os.environ.get("HARIS_SMTP_USERNAME", ""),
        password=os.environ.get("HARIS_SMTP_PASSWORD", ""),
        use_tls=os.environ.get("HARIS_SMTP_USE_TLS", "true").lower() != "false",
        from_address=os.environ.get("HARIS_SMTP_FROM", "noreply@techforpalestine.org"),
        from_name=os.environ.get("HARIS_SMTP_FROM_NAME", "HARIS Security Platform"),
    )
    return EmailSender(config)
