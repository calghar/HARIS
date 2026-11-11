import ipaddress
import socket
from collections.abc import Callable

from .errors import SSRFBlocked

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type Resolver = Callable[[str, int], list[str]]

METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a)
    for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)
METADATA_HOSTS = frozenset({"metadata.google.internal"})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def system_resolver(host: str, port: int) -> list[str]:
    """All addresses ``getaddrinfo`` returns for *host* (deduplicated, ordered)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]).split("%")[0] for info in infos))


def embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    """IPv4 carried inside an IPv4-mapped, NAT64 or 6to4 address, else None."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIX_TO_FOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def is_metadata(ip: IPAddress) -> bool:
    inner = embedded_ipv4(ip)
    return ip in METADATA_ADDRESSES or (
        inner is not None and inner in METADATA_ADDRESSES
    )


def is_blocked(ip: IPAddress) -> bool:
    """True for any non-public address class (including metadata)."""
    inner = embedded_ipv4(ip)
    if inner is not None:
        return is_blocked(inner)
    return is_metadata(ip) or ip.is_multicast or ip.is_reserved or not ip.is_global


def vet_host(
    host: str,
    port: int,
    *,
    allow_private: bool,
    resolver: Resolver = system_resolver,
) -> str:
    """Resolve *host* now and return one address, or raise SSRFBlocked."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = resolver(host, port)
        except OSError as exc:
            raise SSRFBlocked(f"{host} did not resolve") from exc
    else:
        addresses = [host]
    return vet_addresses(host, addresses, allow_private=allow_private)


def vet_addresses(host: str, addresses: list[str], *, allow_private: bool) -> str:
    """Return the first address when every one passes; else raise SSRFBlocked."""
    if host.lower() in METADATA_HOSTS:
        raise SSRFBlocked(f"{host} is a cloud metadata host")
    if not addresses:
        raise SSRFBlocked(f"{host} did not resolve")
    for text in addresses:
        ip = ipaddress.ip_address(text)
        if is_metadata(ip) or (not allow_private and is_blocked(ip)):
            hint = (
                "" if allow_private else " (use --allow-private for internal targets)"
            )
            raise SSRFBlocked(f"{host} resolves to blocked address {text}{hint}")
    return addresses[0]
