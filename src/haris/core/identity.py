import contextlib
import hashlib
import re
import string
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..models import Finding, confidence_from_score
from .confidence import prior_for
from .vuln_class import get_registry, slug

SCHEMA_VERSION = "v1"
FIELD_SEPARATOR = "\x1f"
FINDING_ID_LENGTH = 16
NO_CWE = "CWE-NONE"
DEFAULT_PORTS = {"http": 80, "https": 443}
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
_SLASHES = re.compile(r"/{2,}")


def _percent_normalise(text: str) -> str:
    """Decode escapes of unreserved characters; upper-case the others."""

    def replace(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else f"%{match.group(1).upper()}"

    return _PERCENT.sub(replace, text)


def _split_url(url: str, base_url: str) -> tuple[str, str, str]:
    """Return the normalised (origin, path, query-names) of *url*."""
    parts = urlsplit(urljoin(base_url, url))
    host = parts.hostname or ""
    with contextlib.suppress(UnicodeError):
        host = host.encode("idna").decode("ascii")
    try:
        port = parts.port
    except ValueError:
        port = None
    scheme = parts.scheme.lower()
    netloc = f"[{host}]" if ":" in host else host
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"
    origin = f"{scheme}://{netloc}" if host else ""
    path = _percent_normalise(_SLASHES.sub("/", parts.path)).rstrip("/") or "/"
    names = sorted({name for name, _ in parse_qsl(parts.query, True)})
    return origin, path, "&".join(names)


def normalise_url(url: str, base_url: str = "") -> str:
    """Canonical URL for identity: no fragment, no query values, sorted names."""
    origin, path, query = _split_url(url, base_url)
    return f"{origin}{path}" + (f"?{query}" if query else "")


def normalise_cwe(cwe_id: str) -> str:
    match = re.search(r"\d+", cwe_id)
    return f"CWE-{int(match.group())}" if match else NO_CWE


def identify(finding: Finding, base_url: str = "") -> tuple[str, str]:
    """Return ``(vuln_class, fingerprint)`` without touching *finding*."""
    registry = get_registry()
    class_id = registry.classify(finding)
    known = registry.classes.get(class_id)
    cwe = known.primary_cwe if known else normalise_cwe(finding.cwe_id)
    granularity = known.granularity if known else "parameter"

    origin, path, query = _split_url(finding.url, base_url)
    method = finding.method.upper()
    parameter = finding.parameter
    url = f"{origin}{path}" + (f"?{query}" if query else "")
    if granularity == "host":
        # Header/cookie name lives in `parameter`; the title tells them apart otherwise.
        url, method, parameter = origin, "", parameter or slug(finding.title)
    elif granularity == "path":
        parameter = ""

    raw = FIELD_SEPARATOR.join([SCHEMA_VERSION, cwe, class_id, url, method, parameter])
    return class_id, hashlib.sha256(raw.encode()).hexdigest()


def fingerprint(finding: Finding, base_url: str = "") -> str:
    return identify(finding, base_url)[1]


def assign_identity(finding: Finding, base_url: str = "") -> None:
    """Set class, fingerprint, ``finding_id`` and the derived confidence."""
    finding.vuln_class, finding.fingerprint = identify(finding, base_url)
    finding.finding_id = finding.fingerprint[:FINDING_ID_LENGTH]
    finding.confidence_score = prior_for(finding)
    finding.confidence = confidence_from_score(finding.confidence_score)
