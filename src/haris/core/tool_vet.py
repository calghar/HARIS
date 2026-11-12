import logging

from ..models import Target
from ..net.egress_proxy import EgressProxy
from ..net.errors import SSRFBlocked
from ..net.policy import NetworkPolicy
from ..net.ssrf import Resolver, system_resolver, vet_host
from ..scanners.base import ExternalToolScanner
from .scanner import BaseScanner

logger = logging.getLogger(__name__)


def egress_proxy_for(
    scanners: list[BaseScanner],
    target: Target,
    target_ip: str,
    policy: NetworkPolicy,
    resolver: Resolver | None,
) -> EgressProxy | None:
    """Unstarted proxy pinned to the vetted address; None without external tools."""
    if not any(isinstance(s, ExternalToolScanner) for s in scanners):
        return None
    pinned = {(target.hostname, target.port): target_ip} if target.hostname else {}
    return EgressProxy(
        allow_private=policy.allow_private,
        pinned=pinned,
        resolver=resolver or system_resolver,
    )


def external_target_block(
    scanner: BaseScanner,
    target: Target,
    policy: NetworkPolicy,
    resolver: Resolver | None,
) -> str | None:
    """Fresh SSRF check of the target host. None means the tool may start."""
    if not isinstance(scanner, ExternalToolScanner):
        return None
    host = target.hostname
    if not host:
        return f"{scanner.name} was not started: target host is missing"
    try:
        vet_host(
            host,
            target.port,
            allow_private=policy.allow_private,
            resolver=resolver or system_resolver,
        )
    except SSRFBlocked as exc:
        logger.info("Blocked %s before start: %s", scanner.name, exc)
        return f"{scanner.name} was not started: {exc}"
    return None
