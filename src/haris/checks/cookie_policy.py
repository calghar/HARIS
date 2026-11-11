import logging
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

NAME_KEY = "__name__"
VALUE_KEY = "__value__"

# Names that identify a login session; anti-forgery cookies are excluded on purpose
# (they must be readable by scripts).
SESSION_NAME = re.compile(r"(?i)sess|(?:^|[_.-])sid(?:$|[_.-])|auth|jwt|login|token")
ANTI_FORGERY_NAME = re.compile(r"(?i)csrf|xsrf")

# Default session cookie names mapped to the framework they reveal.
FRAMEWORK_SESSIONS: dict[str, str] = {
    "phpsessid": "PHP",
    "jsessionid": "Java EE / Tomcat",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "Classic ASP",
    "rack.session": "Ruby Rack",
    "connect.sid": "Node.js / Connect",
    "ci_session": "CodeIgniter",
    "laravel_session": "Laravel",
    "django_session": "Django (non-default name variant)",
    "cfid": "ColdFusion",
    "cftoken": "ColdFusion",
}

# A Domain attribute equal to one of these is sent to every site under the suffix.
PUBLIC_SUFFIXES = frozenset(
    {".com", ".net", ".org", ".io", ".co", ".gov", ".edu"}
    | {".com.au", ".co.uk", ".co.nz", ".co.za"}
)


def parse_set_cookie(raw: str) -> dict[str, str] | None:
    """Attributes of one ``Set-Cookie`` header (lower-case keys), or ``None``."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    attrs = {NAME_KEY: name.strip(), VALUE_KEY: value.strip()}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return attrs


def is_session_cookie(name: str) -> bool:
    if ANTI_FORGERY_NAME.search(name):
        return False
    return name.lower() in FRAMEWORK_SESSIONS or bool(SESSION_NAME.search(name))


def is_public_suffix(domain: str) -> bool:
    return "." + domain.lstrip(".").lower() in PUBLIC_SUFFIXES


def lifetime_seconds(attrs: dict[str, str]) -> int | None:
    """Lifetime in seconds (``Max-Age`` wins); ``None`` for a session-only cookie."""
    max_age = attrs.get("max-age", "").strip()
    if max_age:
        try:
            return int(max_age)
        except ValueError:
            logger.debug("Could not parse Max-Age: %r", max_age)
    expires = attrs.get("expires", "").strip()
    if expires:
        try:
            expires_at = parsedate_to_datetime(expires)
        except (TypeError, ValueError):
            logger.debug("Could not parse Expires: %r", expires)
            return None
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
    return None
