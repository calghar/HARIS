import hashlib
import posixpath
import re
import secrets
import threading
import weakref
from enum import StrEnum
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict

from ..models import VerificationOracle
from ..net import ScopedClient, ScopedResponse
from .requesting import media_type, try_request
from .validators import validator_for

CONTROL_PREFIX = "haris-"
CONTROL_TOKEN_BYTES = 8
MAX_EXTRA_CONTROLS = 10
LENGTH_BUCKET_BYTES = 512
SIMILAR_LENGTH_FLOOR = 64
SIMILAR_LENGTH_RATIO = 0.05
CATCH_ALL_MIN_SUCCESSES = 2

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DIGIT_RUNS = re.compile(r"\d{4,}")
_TOKENS = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


class HostClass(StrEnum):
    CATCH_ALL = "catch_all"
    UNSTABLE = "unstable"
    NORMAL = "normal"


class ResponseFingerprint(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: int
    content_type: str
    length: int
    length_bucket: int
    body_hash: str
    title: str
    location: str


class PathVerdict(BaseModel):
    """Whether a 2xx path probe may become a finding, and which oracle decided."""

    model_config = ConfigDict(frozen=True)

    report: bool
    reason: str
    oracle: VerificationOracle
    validated: bool = False
    span: str = ""


def _scrub(text: str, path: str) -> str:
    """Drop the requested path, long digit runs and token-like strings."""
    if path not in ("", "/"):
        for variant in dict.fromkeys((path, quote(path), quote(path, safe=""))):
            text = text.replace(variant, "")
    return " ".join(_TOKENS.sub("", _DIGIT_RUNS.sub("", text)).split())


def fingerprint(resp: ScopedResponse, path: str) -> ResponseFingerprint:
    """Fingerprint *resp*, which answered a request for *path*."""
    title = _TITLE.search(resp.text)
    return ResponseFingerprint(
        status=resp.status_code,
        content_type=media_type(resp),
        length=len(resp.content),
        length_bucket=len(resp.content) // LENGTH_BUCKET_BYTES,
        body_hash=hashlib.sha256(_scrub(resp.text, path).encode()).hexdigest(),
        title=" ".join(title.group(1).split()).lower() if title else "",
        location=_scrub(resp.headers.get("location", ""), path),
    )


def matches(response: ResponseFingerprint, control: ResponseFingerprint) -> bool:
    """The similarity rule: *response* looks like the control's soft-404 page."""
    if response.status != control.status:
        return False
    if 300 <= response.status < 400:
        return response.location == control.location
    if response.content_type != control.content_type:
        return False
    if response.body_hash == control.body_hash:
        return True
    tolerance = max(SIMILAR_LENGTH_FLOOR, SIMILAR_LENGTH_RATIO * control.length)
    return response.title == control.title and (
        abs(response.length - control.length) <= tolerance
    )


def _same_page(a: ResponseFingerprint, b: ResponseFingerprint) -> bool:
    """Two probes returned one generic page (empty titles prove nothing)."""
    if a.body_hash == b.body_hash and a.content_type == b.content_type:
        return True
    return bool(a.title) and matches(a, b)


def _control_key(path: str) -> tuple[str, str] | None:
    """(directory, extension) of a path; ``None`` when the root controls cover it."""
    directory, name = posixpath.split(urlsplit(path).path.rstrip("/"))
    extension = posixpath.splitext(name)[1]
    if directory in ("", "/") and extension in ("", ".html"):
        return None
    return directory, extension


class Baseline:
    """Soft-404 controls for one host, fetched lazily and cached for the scan."""

    def __init__(self, client: ScopedClient, base_url: str) -> None:
        parts = urlsplit(base_url)
        self._client = client
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._token = CONTROL_PREFIX + secrets.token_hex(CONTROL_TOKEN_BYTES)
        self._lock = threading.Lock()
        self._base: list[ResponseFingerprint] | None = None
        self._extra: dict[tuple[str, str], ResponseFingerprint | None] = {}

    def _control(self, path: str) -> ResponseFingerprint | None:
        resp = try_request(self._client, "GET", self._origin + path)
        return fingerprint(resp, path) if resp is not None else None

    def base_controls(self) -> list[ResponseFingerprint]:
        with self._lock:
            if self._base is None:
                token = self._token
                fetched = (
                    self._control(p)
                    for p in (f"/{token}", f"/{token}/", f"/{token}.html")
                )
                self._base = [f for f in fetched if f is not None]
            return self._base

    def _extra_control(self, path: str) -> ResponseFingerprint | None:
        key = _control_key(path)
        if key is None:
            return None
        with self._lock:
            if key not in self._extra:
                if len(self._extra) >= MAX_EXTRA_CONTROLS:
                    return None
                directory, extension = key
                self._extra[key] = self._control(
                    f"{directory.rstrip('/')}/{self._token}{extension}"
                )
            return self._extra[key]

    def host_class(self) -> HostClass:
        controls = self.base_controls()
        successes = sum(200 <= c.status < 300 for c in controls)
        if successes >= CATCH_ALL_MIN_SUCCESSES:
            return HostClass.CATCH_ALL
        if len({c.status // 100 for c in controls}) > 1:
            return HostClass.UNSTABLE
        return HostClass.NORMAL

    def judge(self, path: str, resp: ScopedResponse) -> PathVerdict:
        """Decide whether *resp* to a probe of *path* is evidence of a real resource."""
        if not 200 <= resp.status_code < 300:
            return PathVerdict(
                report=False,
                reason="not a 2xx response",
                oracle=VerificationOracle.NONE,
            )
        probe = fingerprint(resp, path)
        controls = [*self.base_controls()]
        extra = self._extra_control(path)
        if extra is not None:
            controls.append(extra)
        if any(matches(probe, c) for c in controls):
            return PathVerdict(
                report=False,
                reason="matches the soft-404 control response",
                oracle=VerificationOracle.SOFT404,
            )
        validator = validator_for(path)
        if validator is not None:
            outcome = validator.validate(resp)
            return PathVerdict(
                report=outcome.passed,
                reason=outcome.reason,
                oracle=VerificationOracle.CONTENT_VALIDATOR,
                validated=outcome.passed,
                span=outcome.span,
            )
        host = self.host_class()
        if host is not HostClass.NORMAL:
            return PathVerdict(
                report=False,
                reason=f"host is {host.value} and the path has no validator",
                oracle=VerificationOracle.SOFT404,
            )
        return PathVerdict(
            report=True, reason="no soft-404 match", oracle=VerificationOracle.NONE
        )

    def judge_many(
        self, responses: dict[str, ScopedResponse]
    ) -> dict[str, PathVerdict]:
        """Judge each probe, then drop unvalidated hits that share one generic page."""
        verdicts = {path: self.judge(path, r) for path, r in responses.items()}
        prints = {
            path: fingerprint(r, path)
            for path, r in responses.items()
            if 200 <= r.status_code < 300
        }
        for path, verdict in verdicts.items():
            if not verdict.report or verdict.validated:
                continue
            if any(
                other != path and _same_page(prints[path], prints[other])
                for other in prints
            ):
                verdicts[path] = PathVerdict(
                    report=False,
                    reason="several paths returned the same page",
                    oracle=VerificationOracle.SOFT404,
                )
        return verdicts


_BASELINES: weakref.WeakKeyDictionary[ScopedClient, dict[str, Baseline]] = (
    weakref.WeakKeyDictionary()
)
_BASELINES_LOCK = threading.Lock()


def get_baseline(client: ScopedClient, base_url: str) -> Baseline:
    """The scan's baseline for the host of *base_url* (one per client and host)."""
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    with _BASELINES_LOCK:
        hosts = _BASELINES.setdefault(client, {})
        if origin not in hosts:
            hosts[origin] = Baseline(client, base_url)
        return hosts[origin]
