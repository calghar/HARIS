import socket
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from haris.checks.dns_wire import CAA, TXT

LOOPBACK = "127.0.0.1"
TYPES = {"TXT": TXT, "CAA": CAA}
RCODE_SERVFAIL = 2
NAME_POINTER = b"\xc0\x0c"
CHUNK = 255

type Records = dict[tuple[str, str], list[str]]


def _qname(query: bytes) -> tuple[str, int, bytes]:
    end = 12
    labels = []
    while query[end]:
        labels.append(query[end + 1 : end + 1 + query[end]].decode())
        end += 1 + query[end]
    question = query[12 : end + 5]
    (qtype,) = struct.unpack(">H", query[end + 1 : end + 3])
    return ".".join(labels).lower(), qtype, question


def _rdata(kind: str, text: str) -> bytes:
    if kind == "CAA":
        tag, value = text.split(" ", 1)
        return bytes([0, len(tag)]) + tag.encode() + value.encode()
    raw = text.encode()
    chunks = [raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


def answer(query: bytes, records: Records, servfail: set[str]) -> bytes:
    name, qtype, question = _qname(query)
    kind = next(k for k, v in TYPES.items() if v == qtype)
    qid = query[:2]
    if name in servfail:
        return (
            qid + struct.pack(">HHHHH", 0x8180 | RCODE_SERVFAIL, 1, 0, 0, 0) + question
        )
    rows = records.get((name, kind), [])
    body = b""
    for text in rows:
        data = _rdata(kind, text)
        body += NAME_POINTER + struct.pack(">HHIH", qtype, 1, 60, len(data)) + data
    return qid + struct.pack(">HHHHH", 0x8180, 1, len(rows), 0, 0) + question + body


@contextmanager
def dns_server(
    records: Records, servfail: set[str] | None = None
) -> Iterator[tuple[int, list[str]]]:
    """A UDP DNS server on 127.0.0.1; yields its port and the names queried."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOOPBACK, 0))
    sock.settimeout(0.1)
    stop = threading.Event()
    seen: list[str] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                query, peer = sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                return
            name, qtype, _ = _qname(query)
            seen.append(f"{name}/{qtype}")
            sock.sendto(answer(query, records, servfail or set()), peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield int(sock.getsockname()[1]), seen
    finally:
        stop.set()
        thread.join()
        sock.close()
