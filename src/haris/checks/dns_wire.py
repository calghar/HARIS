import re
import secrets
import socket
import struct
from pathlib import Path

TXT = 16
CAA = 257
DNS_PORT = 53
HEADER_BYTES = 12
POINTER_MASK = 0xC0
MAX_NAME_JUMPS = 32
MAX_UDP_BYTES = 4096
RCODE_NXDOMAIN = 3
RESOLV_CONF = Path("/etc/resolv.conf")
_NAMESERVER = re.compile(r"^nameserver\s+(\S+)", re.MULTILINE)


class DnsError(Exception):
    """The lookup failed (timeout, server error, malformed reply); not 'no record'."""


def system_nameservers(path: Path = RESOLV_CONF) -> list[str]:
    try:
        return _NAMESERVER.findall(path.read_text())
    except OSError:
        return []


def build_query(name: str, rrtype: int, query_id: int) -> bytes:
    labels = [label.encode("ascii") for label in name.rstrip(".").split(".")]
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # RD set
    return header + qname + struct.pack(">HH", rrtype, 1)


def _skip_name(data: bytes, offset: int) -> int:
    for _ in range(MAX_NAME_JUMPS):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & POINTER_MASK == POINTER_MASK:
            return offset + 2
        offset += 1 + length
    raise DnsError("malformed name")


def _txt(rdata: bytes) -> str:
    parts, i = [], 0
    while i < len(rdata):
        size = rdata[i]
        parts.append(rdata[i + 1 : i + 1 + size].decode("utf-8", errors="replace"))
        i += 1 + size
    return "".join(parts)


def _caa(rdata: bytes) -> str:
    flags, tag_length = rdata[0], rdata[1]
    tag = rdata[2 : 2 + tag_length].decode("ascii", errors="replace")
    value = rdata[2 + tag_length :].decode("utf-8", errors="replace")
    return f'{flags} {tag} "{value}"'


def parse_answers(data: bytes, query_id: int, rrtype: int) -> list[str]:
    """Text of each answer of *rrtype*; empty for NOERROR/NXDOMAIN without one."""
    if len(data) < HEADER_BYTES:
        raise DnsError("short reply")
    rid, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != query_id:
        raise DnsError("reply id does not match the query")
    if flags & 0x0200:
        raise DnsError("reply truncated")
    rcode = flags & 0x000F
    if rcode == RCODE_NXDOMAIN:
        return []
    if rcode != 0:
        raise DnsError(f"server returned rcode {rcode}")
    offset = HEADER_BYTES
    for _ in range(questions):
        offset = _skip_name(data, offset) + 4
    records: list[str] = []
    for _ in range(answers):
        offset = _skip_name(data, offset)
        kind, _, _, length = struct.unpack(">HHIH", data[offset : offset + 10])
        rdata = data[offset + 10 : offset + 10 + length]
        offset += 10 + length
        if kind == rrtype == TXT:
            records.append(_txt(rdata))
        elif kind == rrtype == CAA:
            records.append(_caa(rdata))
    return records


class UdpResolver:
    """Minimal stub resolver: one UDP query per lookup, first reachable server."""

    def __init__(
        self, servers: list[str], *, port: int = DNS_PORT, timeout: float = 3.0
    ) -> None:
        self._servers = servers
        self._port = port
        self._timeout = timeout

    def lookup(self, name: str, rrtype: int) -> list[str]:
        if not self._servers:
            raise DnsError("no nameserver configured")
        query_id = secrets.randbits(16)
        query = build_query(name, rrtype, query_id)
        last: Exception = DnsError("no nameserver answered")
        for server in self._servers:
            family = socket.AF_INET6 if ":" in server else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self._timeout)
                try:
                    sock.sendto(query, (server, self._port))
                    data, _ = sock.recvfrom(MAX_UDP_BYTES)
                except OSError as exc:
                    last = exc
                    continue
            return parse_answers(data, query_id, rrtype)
        raise DnsError(str(last))
