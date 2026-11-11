import hmac
import logging
import os

from starlette.requests import Request

from .email import EmailSender, SMTPConfig
from .oidc import OIDCClient, OIDCConfig

logger = logging.getLogger(__name__)

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


def email_domain_allowed(email: str) -> bool:
    allowed = get_allowed_domains()
    if not allowed:
        return True
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    return domain.lower() in allowed


def emailed_link_base(request: Request) -> str | None:
    """Public URL, or the request base when SMTP is off. None means do not send."""
    configured = os.environ.get("HARIS_PUBLIC_URL", "").strip().rstrip("/")
    if configured:
        return configured
    if not env_flag("HARIS_SMTP_ENABLED"):
        return str(request.base_url).rstrip("/")
    logger.error("HARIS_PUBLIC_URL is unset; refusing to send a verification email")
    return None


def trusted_hosts() -> list[str]:
    raw = os.environ.get("HARIS_ALLOWED_HOSTS", "")
    return [host.strip() for host in raw.split(",") if host.strip()]


def setup_enabled() -> bool:
    return bool(os.environ.get("HARIS_SETUP_TOKEN", ""))


def setup_token_matches(supplied: str) -> bool:
    expected = os.environ.get("HARIS_SETUP_TOKEN", "")
    if not expected:
        return False
    return hmac.compare_digest(supplied, expected)


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
