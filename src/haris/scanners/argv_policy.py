import re
from typing import Any

from ..data.scanner_config import get_extra_args_allowlist

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.,:;@%+/=][A-Za-z0-9_.,:;@%+/=-]*$")


class ExtraArgsError(ValueError):
    pass


def _check_value(scanner: str, flag: str, value: str) -> None:
    if not _SAFE_VALUE.match(value):
        raise ExtraArgsError(
            f"extra_args value {value!r} for {flag} is not allowed for {scanner}"
        )


def validate_extra_args(scanner: str, args: Any) -> list[str]:
    """Return *args* if every flag is in the scanner's allow-list, else raise."""
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ExtraArgsError(f"extra_args for {scanner} must be a list of strings")
    allowed = get_extra_args_allowlist(scanner)
    index = 0
    while index < len(args):
        token = args[index]
        flag, joined, inline = token.partition("=")
        arity = allowed.get(flag)
        if arity is None:
            raise ExtraArgsError(
                f"extra_args flag {token!r} is not allowed for {scanner}; "
                f"allowed: {', '.join(sorted(allowed)) or 'none'}"
            )
        if joined:
            if arity != 1:
                raise ExtraArgsError(f"extra_args flag {flag!r} takes no value")
            _check_value(scanner, flag, inline)
            index += 1
            continue
        values = args[index + 1 : index + 1 + arity]
        if len(values) != arity:
            raise ExtraArgsError(f"extra_args flag {flag!r} needs {arity} value(s)")
        for value in values:
            _check_value(scanner, flag, value)
        index += 1 + arity
    return list(args)
