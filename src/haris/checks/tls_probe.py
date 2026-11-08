import logging
import socket
import ssl
import warnings

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

LEGACY_CIPHERS = "ALL:@SECLEVEL=0"
# (display name, ssl.TLSVersion member): accessing these members warns as deprecated.
LEGACY_PROTOCOLS = (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"))
HOSTNAME_MISMATCH_CODES = frozenset({62, 64})
TIME_CODES = frozenset({9, 10})
MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)
TAG_UTC_TIME = 0x17
TAG_EXPLICIT_VERSION = 0xA0
UTC_YEAR_PIVOT = 50


class TlsHandshake(BaseModel):
    model_config = ConfigDict(frozen=True)

    der: bytes
    protocol: str
    cipher: tuple[str, str, int] | None


def _client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _handshake(
    ip: str, port: int, host: str, ctx: ssl.SSLContext, timeout: float
) -> TlsHandshake:
    with (
        socket.create_connection((ip, port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls,
    ):
        cipher = tls.cipher()
        return TlsHandshake(
            der=tls.getpeercert(binary_form=True) or b"",
            protocol=tls.version() or "",
            cipher=(cipher[0], cipher[1], cipher[2] or 0) if cipher else None,
        )


def fetch_certificate(ip: str, port: int, host: str, timeout: float) -> TlsHandshake:
    """Handshake without verification, so bad certificates stay readable."""
    return _handshake(ip, port, host, _client_context(), timeout)


def supports_legacy_protocol(
    ip: str, port: int, host: str, member: str, timeout: float
) -> bool:
    """True when the server completes a handshake pinned to one deprecated version."""
    ctx = _client_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ctx.maximum_version = getattr(ssl.TLSVersion, member)
    ctx.set_ciphers(LEGACY_CIPHERS)
    try:
        _handshake(ip, port, host, ctx, timeout)
    except (OSError, ssl.SSLError):
        return False
    return True


def verification_failure(
    ip: str, port: int, host: str, der: bytes, timeout: float, *, trust_peer: bool
) -> ssl.SSLCertVerificationError | None:
    """Verify the chain, or (``trust_peer``) only the hostname and dates of the leaf."""
    if trust_peer:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers(LEGACY_CIPHERS)
    try:
        _handshake(ip, port, host, ctx, timeout)
    except ssl.SSLCertVerificationError as exc:
        return exc
    return None


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the DER element at *pos*."""
    tag, length, pos = data[pos], data[pos + 1], pos + 2
    if length & 0x80:
        count = length & 0x7F
        length, pos = int.from_bytes(data[pos : pos + count], "big"), pos + count
    return tag, pos, pos + length


def _asn1_time(tag: int, raw: bytes) -> str:
    """UTCTime or GeneralizedTime in the format ``getpeercert()`` reports."""
    text = raw.decode("ascii")
    if tag == TAG_UTC_TIME:
        year = int(text[:2])
        year += 1900 if year >= UTC_YEAR_PIVOT else 2000
        text = text[2:]
    else:
        year, text = int(text[:4]), text[4:]
    month, day, hour, minute, second = (int(text[i : i + 2]) for i in range(0, 10, 2))
    return (
        f"{MONTHS[month - 1]} {day:2d} {hour:02d}:{minute:02d}:{second:02d} {year} GMT"
    )


def cert_validity(der: bytes) -> dict[str, str] | None:
    """``notBefore``/``notAfter`` of a DER certificate; ``None`` when unparsable."""
    try:
        _, body, _ = _tlv(der, 0)
        _, pos, _ = _tlv(der, body)
        tag, _, end = _tlv(der, pos)
        if tag == TAG_EXPLICIT_VERSION:
            pos = end
        for _ in range(3):  # serial, signature algorithm, issuer
            _, _, pos = _tlv(der, pos)
        _, pos, _ = _tlv(der, pos)
        not_before = _tlv(der, pos)
        not_after = _tlv(der, not_before[2])
        return {
            "notBefore": _asn1_time(not_before[0], der[not_before[1] : not_before[2]]),
            "notAfter": _asn1_time(not_after[0], der[not_after[1] : not_after[2]]),
        }
    except (IndexError, ValueError):
        logger.warning("Could not parse the certificate validity period")
        return None
