import re
from collections.abc import Mapping

REDACTED = "[REDACTED]"
_SENSITIVE_NAME = re.compile(r"(?i)(token|secret|api[-_]?key|auth|session)")
_ALWAYS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Copy *headers* with the values of credential-bearing names replaced."""
    return {
        name: REDACTED
        if name.lower() in _ALWAYS or _SENSITIVE_NAME.search(name)
        else value
        for name, value in headers.items()
    }
