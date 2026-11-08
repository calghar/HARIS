import re

_MD_SPECIAL = re.compile(r"([\\`*\[\]()|])")
_BACKTICKS = re.compile(r"`+")
_WHITESPACE = re.compile(r"\s+")
_XML_ILLEGAL = re.compile(r"[^\t\n\r\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _angles(text: str) -> str:
    return text.replace("<", "&lt;").replace(">", "&gt;")


def md_text(text: str) -> str:
    """One-line Markdown text with HTML and link syntax neutralised."""
    flat = _WHITESPACE.sub(" ", text).strip().replace("&", "&amp;")
    return _MD_SPECIAL.sub(r"\\\1", _angles(flat))


def md_code(text: str, *, angles: bool = True) -> str:
    """Code span its content cannot close; ``angles=False`` leaves ``<>`` raw."""
    flat = _WHITESPACE.sub(" ", text).strip().replace("|", "\\|")
    longest = max((len(m) for m in _BACKTICKS.findall(flat)), default=0)
    fence = "`" * (longest + 1)
    body = _angles(flat) if angles else flat
    return f"{fence} {body} {fence}" if flat else "-"


def md_fence(text: str, *, angles: bool = True) -> str:
    """Fenced block longer than any backtick run inside it."""
    longest = max((len(m) for m in _BACKTICKS.findall(text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{_angles(text) if angles else text}\n{fence}"


def csv_cell(value: str) -> str:
    """Prefix formula-leading cells with ``'`` so spreadsheets read them as text."""
    return f"'{value}" if value.startswith(_CSV_FORMULA) else value


def xml_text(value: str) -> str:
    """Drop control characters XML 1.0 forbids."""
    return _XML_ILLEGAL.sub("", value)
