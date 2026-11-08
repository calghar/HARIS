import fnmatch
import ipaddress
import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
from fastapi import HTTPException

from ..db.targets import AuthorizedTarget, TargetRepository
from ..models import Scope, Target
from ..net import NetworkError, NetworkPolicy, ScopedClient, SSRFBlocked
from ..net.ssrf import Resolver, system_resolver, vet_addresses

logger = logging.getLogger(__name__)

PROOF_PREFIX = "haris-verify="
PROOF_TOKEN_BYTES = 16
VERIFICATION_MAX_AGE = timedelta(days=30)
DNS_LABEL = "_haris-verify"
WELL_KNOWN_PATH = "/.well-known/haris-verify.txt"
DNS_TIMEOUT_S = 5.0
PROOF_MAX_REQUESTS = 4
PROOF_MAX_BODY_BYTES = 1024
ALLOWED_SCHEMES = frozenset({"http", "https"})
VETTING_PORT = 443

type TxtLookup = Callable[[str], list[str]]
type ClientFactory = Callable[[Target, NetworkPolicy], ScopedClient]


def dns_txt(name: str) -> list[str]:
    """TXT records of *name* as joined strings; empty when none or unresolvable."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT_S)
    except dns.exception.DNSException:
        return []
    return ["".join(part.decode() for part in rdata.strings) for rdata in answers]


def url_host(url: str) -> str:
    """Lower-case hostname of an http(s) URL; 400 for anything else."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ALLOWED_SCHEMES or not host:
        raise HTTPException(status_code=400, detail="target_url must be http(s)")
    return host


class TargetAuthoriser:
    """SSRF guard, allow-list and ownership proof for web-started scans."""

    def __init__(
        self,
        repo: TargetRepository,
        allowlist: list[str],
        *,
        resolver: Resolver = system_resolver,
        txt_lookup: TxtLookup = dns_txt,
        client_factory: ClientFactory | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._repo = repo
        self._allowlist = allowlist
        self._resolver = resolver
        self._txt_lookup = txt_lookup
        self._client_factory = client_factory or self._default_client
        self._clock = clock

    def _default_client(self, target: Target, policy: NetworkPolicy) -> ScopedClient:
        return ScopedClient(target, policy, resolver=self._resolver)

    def vet_host(self, host: str) -> None:
        """400 unless every address of *host* is allowed by the server policy."""
        policy = NetworkPolicy.from_env()
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            try:
                addresses = self._resolver(host, VETTING_PORT)
            except OSError as exc:
                logger.info("Target %s does not resolve: %s", host, exc)
                raise HTTPException(
                    status_code=400, detail="Target host does not resolve"
                ) from exc
        try:
            vet_addresses(host, addresses, allow_private=policy.allow_private)
        except SSRFBlocked as exc:
            logger.warning("Blocked target %s: %s", host, exc)
            raise HTTPException(
                status_code=400, detail="Target address is not allowed"
            ) from exc

    def is_authorised(self, user_id: str, host: str) -> bool:
        if any(fnmatch.fnmatchcase(host, pattern) for pattern in self._allowlist):
            return True
        row = self._repo.get(user_id, host)
        return row is not None and self.is_current(row)

    def is_current(self, row: AuthorizedTarget) -> bool:
        """True when *row* was verified within the last 30 days."""
        return bool(row.verified_at) and datetime.fromisoformat(row.verified_at) >= (
            self._clock() - VERIFICATION_MAX_AGE
        )

    def list_for_user(self, user_id: str) -> list[AuthorizedTarget]:
        return self._repo.list_for_user(user_id)

    def remove(self, user_id: str, host: str) -> bool:
        return self._repo.delete(user_id, host.lower().rstrip("."))

    def check_scan_target(self, user_id: str, url: str) -> str:
        """Return the host when the user may scan *url*; 400 SSRF, 403 unauthorised."""
        host = url_host(url)
        self.vet_host(host)
        if not self.is_authorised(user_id, host):
            raise HTTPException(
                status_code=403,
                detail="Target not authorised: prove ownership via /api/v1/targets",
            )
        return host

    def issue(self, user_id: str, host: str) -> AuthorizedTarget:
        """The (user, host) proof row, created with a fresh token on first call."""
        host = host.lower().rstrip(".")
        self._repo.add(
            user_id,
            host,
            PROOF_PREFIX + secrets.token_hex(PROOF_TOKEN_BYTES),
            self._clock().isoformat(timespec="seconds"),
        )
        return self._row(user_id, host)

    def _row(self, user_id: str, host: str) -> AuthorizedTarget:
        row = self._repo.get(user_id, host)
        if row is None:
            raise HTTPException(status_code=404, detail="Target not found")
        return row

    def verify(self, user_id: str, host: str) -> AuthorizedTarget:
        """Check DNS then file proof for *host*; the row is verified on success."""
        host = host.lower().rstrip(".")
        self.vet_host(host)
        row = self.issue(user_id, host)
        method = self._dns_proof(host, row.proof_token) or self._file_proof(
            host, row.proof_token
        )
        if method:
            self._repo.mark_verified(
                user_id, host, method, self._clock().isoformat(timespec="seconds")
            )
        return self._row(user_id, host)

    def _dns_proof(self, host: str, token: str) -> str:
        for name in (host, f"{DNS_LABEL}.{host}"):
            if any(record.strip() == token for record in self._txt_lookup(name)):
                return "dns"
        return ""

    def _file_proof(self, host: str, token: str) -> str:
        """Fetch the well-known file on the exact host; redirects are never followed."""
        target = Target(
            base_url=f"https://{host}",
            scope=Scope(
                allowed_methods=["GET"],
                follow_redirects=False,
                max_requests=PROOF_MAX_REQUESTS,
            ),
        )
        policy = NetworkPolicy.from_env().model_copy(
            update={"max_body_bytes": PROOF_MAX_BODY_BYTES}
        )
        with self._client_factory(target, policy) as client:
            for scheme in ("https", "http"):
                try:
                    response = client.get(f"{scheme}://{host}{WELL_KNOWN_PATH}")
                except NetworkError as exc:
                    logger.info("Proof fetch %s://%s failed: %s", scheme, host, exc)
                    continue
                body = response.content.decode("utf-8", errors="replace").strip()
                return "file" if response.status_code == 200 and body == token else ""
        return ""
