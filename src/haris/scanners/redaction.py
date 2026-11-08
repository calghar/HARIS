import re
from typing import Any

from ..models.target import Target

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 4

_SECRET_NAME = r"(?:[\w-]*(?:token|secret|api[-_]?key|auth|session)[\w-]*)"
# Header lines in free text (raw requests, curl commands, JSON-escaped dumps).
_TEXT_HEADER = re.compile(
    r"(?i)(?:(?<![\w-])|(?<=\\n)|(?<=\\r))"
    r"((?:proxy-)?authorization|(?:set-)?cookie|x-[\w-]*"
    r"(?:token|secret|api[-_]?key|auth|session)[\w-]*)(\s*:\s*)([^\r\n\"'\\]+)"
)
# Header names used as dict keys.
_KEY_NAME = re.compile(
    rf"(?i)^(?:(?:proxy-)?authorization|(?:set-)?cookie|{_SECRET_NAME})$"
)


def secrets_from(target: Target) -> tuple[str, ...]:
    """Collect the credential values the target would send to a tool."""
    auth = target.auth
    candidates = [auth.header_value, auth.cookie_value, auth.password, auth.username]
    candidates.extend(auth.as_headers().values())
    candidates.extend(value.split()[-1] for value in list(candidates) if value.strip())
    unique = {c for c in candidates if len(c) >= MIN_SECRET_LENGTH}
    return tuple(sorted(unique, key=len, reverse=True))


def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Mask sensitive header values and any known credential in *text*."""
    text = _TEXT_HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def redact_obj(obj: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Recursively redact strings; dict values under sensitive keys are masked."""
    if isinstance(obj, str):
        return redact_text(obj, secrets)
    if isinstance(obj, list):
        return [redact_obj(item, secrets) for item in obj]
    if isinstance(obj, dict):
        return {
            key: REDACTED
            if isinstance(key, str) and _KEY_NAME.match(key) and isinstance(value, str)
            else redact_obj(value, secrets)
            for key, value in obj.items()
        }
    return obj


def redact_argv(cmd: list[str], secrets: tuple[str, ...] = ()) -> list[str]:
    return [redact_text(arg, secrets) for arg in cmd]
