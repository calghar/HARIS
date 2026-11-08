import http.cookiejar
import ipaddress
import logging
import random
import threading
import time
from collections.abc import Callable, Mapping
from typing import Self
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from ..models import Target
from .errors import (
    RequestBudgetExceeded,
    ScopeViolation,
    SSRFBlocked,
    TransportError,
)
from .policy import NetworkPolicy
from .ratelimit import TokenBucket
from .redact import redact_headers
from .requestlog import LogEntry, RequestLog, excerpt
from .ssrf import Resolver, system_resolver, vet_addresses
from .transport import PinnedAdapter, ScopedResponse, read_capped, set_cookie_values

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RETRY_STATUSES = frozenset({502, 503, 504})
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 0.5
BACKOFF_JITTER_S = 0.25
RETRY_AFTER_CAP_S = 60.0


class ScopedClient:
    """The one outbound HTTP path for in-process traffic of a scan.

    Enforces scheme, scope, method, SSRF guard (pinned resolution), rate limit
    and request cap on every request and every redirect hop.
    """

    def __init__(
        self,
        target: Target,
        policy: NetworkPolicy | None = None,
        log: RequestLog | None = None,
        *,
        resolver: Resolver = system_resolver,
        adapter_factory: Callable[[str], HTTPAdapter] = PinnedAdapter,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.target = target
        self.policy = policy or NetworkPolicy()
        self.log = log or RequestLog(self.policy.log_capacity)
        self.budget_exceeded = False
        self._scope = target.scope
        self._methods = {m.upper() for m in self._scope.allowed_methods}
        self._auth_headers = target.auth.as_headers()
        self._resolver = resolver
        self._adapter_factory = adapter_factory
        self._sleep = sleep
        self._clock = clock
        self._bucket = TokenBucket(self._scope.rate_limit_rps, clock, sleep)
        self._sent = 0
        self._lock = threading.Lock()
        self._dns_lock = threading.Lock()
        self._vetted: dict[tuple[str, int], str | SSRFBlocked] = {}
        self._mounted: set[tuple[str, str, str]] = set()
        self._session = requests.Session()
        self._session.trust_env = False
        self._session.cookies.set_policy(
            http.cookiejar.DefaultCookiePolicy(allowed_domains=[])
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._session.close()

    @property
    def requests_sent(self) -> int:
        return self._sent

    @property
    def rate_rps(self) -> float:
        return self._bucket.rate

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ScopedResponse:
        return self.request("GET", url, headers=headers)

    def head(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> ScopedResponse:
        return self.request("HEAD", url, headers=headers)

    def preflight(self, url: str) -> str:
        """Run scheme, scope and SSRF checks without sending; return the vetted IP."""
        return self._vet(url, "GET")[2]

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
    ) -> ScopedResponse:
        method = method.upper()
        response = self._fetch(method, url, headers, body)
        chain: list[str] = []
        while (
            self._scope.follow_redirects
            and response.status_code in REDIRECT_STATUSES
            and "location" in response.headers
        ):
            if len(chain) >= self._scope.max_redirect_depth:
                response.redirect_blocked = True
                break
            hop = urljoin(response.url, response.headers["location"])
            if response.status_code == 303 or (
                response.status_code in (301, 302) and method == "POST"
            ):
                method, body = ("HEAD" if method == "HEAD" else "GET"), None
            try:
                response = self._fetch(method, hop, headers, body)
            except (ScopeViolation, SSRFBlocked, RequestBudgetExceeded) as exc:
                logger.info("Redirect to %s blocked: %s", hop, exc)
                response.redirect_blocked = True
                break
            chain.append(hop)
        response.redirect_chain = chain
        return response

    def _vet(self, url: str, method: str) -> tuple[str, int, str]:
        """Steps 1-3 for one hop; returns (host, port, vetted ip)."""
        parts = urlsplit(url)
        if parts.scheme not in ALLOWED_SCHEMES:
            raise ScopeViolation(f"scheme {parts.scheme!r} is not http or https")
        try:
            port = parts.port or DEFAULT_PORTS[parts.scheme]
        except ValueError as exc:
            raise ScopeViolation(f"invalid port in {url}") from exc
        host = parts.hostname
        if not host or not self._scope.is_url_in_scope(url):
            raise ScopeViolation(f"{url} is outside the authorised scope")
        if method not in self._methods:
            raise ScopeViolation(f"method {method} is not in the allowed methods")
        return host, port, self._vet_host(host, port)

    def _vet_host(self, host: str, port: int) -> str:
        """Resolve once per (host, port) per scan; reuse the vetted IP afterwards."""
        key = (host.lower(), port)
        with self._dns_lock:
            cached = self._vetted.get(key)
            if cached is None:
                try:
                    addresses = self._addresses(host, port)
                except OSError as exc:
                    raise TransportError(f"cannot resolve {host}: {exc}") from exc
                try:
                    cached = vet_addresses(
                        host, addresses, allow_private=self.policy.allow_private
                    )
                except SSRFBlocked as exc:
                    cached = exc
                self._vetted[key] = cached
        if isinstance(cached, SSRFBlocked):
            raise SSRFBlocked(str(cached))
        return cached

    def _addresses(self, host: str, port: int) -> list[str]:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return self._resolver(host, port)
        return [host]

    def _consume_budget(self) -> None:
        with self._lock:
            if self._sent >= self._scope.max_requests:
                self.budget_exceeded = True
                raise RequestBudgetExceeded(
                    f"request cap max_requests={self._scope.max_requests} reached"
                )
            self._sent += 1
        self._bucket.acquire()

    def _fetch(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | str | None,
    ) -> ScopedResponse:
        """One hop: vet, then send with retries (every attempt is counted)."""
        host, port, ip = self._vet(url, method)
        throttled = False
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._consume_budget()
            last = attempt == MAX_ATTEMPTS
            try:
                response = self._send(method, url, host, port, ip, headers, body)
            except requests.RequestException as exc:
                if last:
                    raise TransportError(f"{method} {url} failed: {exc}") from exc
                self._sleep(self._backoff(attempt))
                continue
            status = response.status_code
            if status in RETRY_STATUSES and not last:
                self._sleep(self._backoff(attempt))
            elif status == 429 and not last:
                if not throttled:
                    self._bucket.halve_rate()
                    throttled = True
                self._sleep(self._retry_after(response, attempt))
            else:
                return response
        raise AssertionError("unreachable: the last attempt returns or raises")

    @staticmethod
    def _backoff(attempt: int) -> float:
        return BACKOFF_BASE_S * 2.0 ** (attempt - 1) + random.uniform(
            0, BACKOFF_JITTER_S
        )

    def _retry_after(self, response: ScopedResponse, attempt: int) -> float:
        try:
            return min(float(response.headers["retry-after"]), RETRY_AFTER_CAP_S)
        except (KeyError, ValueError):
            return self._backoff(attempt)

    def _send(
        self,
        method: str,
        url: str,
        host: str,
        port: int,
        ip: str,
        headers: dict[str, str] | None,
        body: bytes | str | None,
    ) -> ScopedResponse:
        parts = urlsplit(url)
        scheme = parts.scheme
        ip_netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        self._mount(scheme, host, ip_netloc)
        host_header = f"[{host}]" if ":" in host else host
        if port != DEFAULT_PORTS[scheme]:
            host_header = f"{host_header}:{port}"
        wire_headers = {**self._auth_headers, **(headers or {}), "Host": host_header}
        pinned = urlunsplit((scheme, ip_netloc, parts.path or "/", parts.query, ""))
        prepared = self._session.prepare_request(
            requests.Request(method, pinned, headers=wire_headers, data=body)
        )

        request_id = self.log.next_id()
        entry = LogEntry(
            request_id=request_id,
            method=method,
            url=url,
            request_headers=redact_headers(_text_items(prepared.headers)),
            request_body_excerpt=_body_excerpt(prepared.body),
        )
        started = self._clock()
        try:
            raw = self._session.send(
                prepared,
                timeout=self.policy.timeout_s,
                allow_redirects=False,
                verify=self.policy.verify_tls,
                stream=True,
            )
            content = read_capped(raw, self.policy.max_body_bytes)
        except requests.RequestException as exc:
            entry.error = type(exc).__name__
            entry.elapsed_ms = (self._clock() - started) * 1000
            self.log.add(entry)
            raise
        elapsed_ms = (self._clock() - started) * 1000
        entry.status = raw.status_code
        entry.elapsed_ms = elapsed_ms
        entry.response_headers = redact_headers(_text_items(raw.headers))
        entry.response_body_excerpt = excerpt(content)
        self.log.add(entry)
        logger.debug("%s %s -> %d", method, url, raw.status_code)
        return ScopedResponse(
            status_code=raw.status_code,
            url=url,
            headers=CaseInsensitiveDict(raw.headers),
            set_cookies=set_cookie_values(raw),
            content=content,
            request_id=request_id,
            elapsed_ms=elapsed_ms,
        )

    def _mount(self, scheme: str, host: str, ip_netloc: str) -> None:
        key = (scheme, host, ip_netloc)
        with self._lock:
            if key not in self._mounted:
                self._session.mount(
                    f"{scheme}://{ip_netloc}/", self._adapter_factory(host)
                )
                self._mounted.add(key)


def _text_items(headers: Mapping[str, str | bytes]) -> dict[str, str]:
    return {
        k: v.decode("latin-1") if isinstance(v, bytes) else v
        for k, v in headers.items()
    }


def _body_excerpt(body: bytes | str | None) -> str:
    if body is None:
        return ""
    return excerpt(body.encode() if isinstance(body, str) else body)
