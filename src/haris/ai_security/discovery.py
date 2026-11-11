import logging
import threading
import weakref
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..checks.baseline import fingerprint, get_baseline, matches
from ..checks.requesting import PROBE_ERRORS, try_request
from ..models import Target
from ..net import ScopedClient, ScopedResponse
from .body_validators import VALIDATORS, model_names
from .rpc import JSON_RPC_HEADERS, initialize_message
from .signatures import Signature, load_signatures

logger = logging.getLogger(__name__)

STREAM_MAX_BYTES = 4096
STREAM_TIMEOUT_S = 3.0


@dataclass(frozen=True, eq=False)
class Endpoint:
    """A confirmed AI endpoint and the response that proved it."""

    signature: Signature
    url: str
    response: ScopedResponse
    chat_url: str = ""
    models: tuple[str, ...] = ()

    @property
    def capability(self) -> str:
        return self.signature.capability


_DISCOVERIES: weakref.WeakKeyDictionary[ScopedClient, dict[str, list[Endpoint]]] = (
    weakref.WeakKeyDictionary()
)
_LOCK = threading.Lock()


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _ask(client: ScopedClient, origin: str, sig: Signature) -> ScopedResponse | None:
    if sig.stream:
        try:
            return client.stream(
                origin + sig.path,
                max_bytes=STREAM_MAX_BYTES,
                timeout_s=STREAM_TIMEOUT_S,
            )
        except PROBE_ERRORS as exc:
            logger.debug("GET %s skipped: %s", sig.path, exc)
            return None
    headers, body = (
        (JSON_RPC_HEADERS, initialize_message()) if sig.rpc else (None, None)
    )
    return try_request(
        client, sig.method, origin + sig.path, headers=headers, body=body
    )


def discover(client: ScopedClient, target: Target) -> list[Endpoint]:
    """Probe every signature; keep 2xx answers that miss the soft-404 baseline."""
    origin = origin_of(target.base_url)
    controls = get_baseline(client, origin).base_controls()
    found: list[Endpoint] = []
    for sig in load_signatures().signatures:
        resp = _ask(client, origin, sig)
        if resp is None or not 200 <= resp.status_code < 300:
            continue
        probe = fingerprint(resp, sig.path)
        if any(matches(probe, c) for c in controls) or not VALIDATORS[sig.validator](
            resp
        ):
            continue
        chat = origin + sig.chat_path if sig.chat_path else ""
        found.append(
            Endpoint(sig, origin + sig.path, resp, chat, tuple(model_names(resp)))
        )
    with _LOCK:
        _DISCOVERIES.setdefault(client, {})[origin] = found
    return found


def discovery_for(client: ScopedClient, target: Target) -> list[Endpoint]:
    """The scan's discovery result for the target origin, run once if missing."""
    origin = origin_of(target.base_url)
    with _LOCK:
        cached = _DISCOVERIES.get(client, {}).get(origin)
    return cached if cached is not None else discover(client, target)
