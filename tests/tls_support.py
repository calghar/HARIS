import datetime
import ipaddress
import socket
import ssl
import tempfile
import threading
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

LOOPBACK = "127.0.0.1"
KEY_BITS = 2048
LEGACY_CIPHERS = "ALL:@SECLEVEL=0"


def make_certificate(
    *,
    not_before_days: int = -30,
    not_after_days: int = 365,
    dns_names: tuple[str, ...] = (),
    ips: tuple[str, ...] = (LOOPBACK,),
) -> tuple[bytes, bytes, x509.Certificate]:
    """Self-signed certificate and key (PEM) valid from/to now plus the given days."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "haris-test")])
    now = datetime.datetime.now(datetime.UTC)
    names: list[x509.GeneralName] = [x509.DNSName(d) for d in dns_names]
    names += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_days))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem, cert


@contextmanager
def tls_server(
    cert_pem: bytes,
    key_pem: bytes,
    *,
    legacy_only: bool = False,
) -> Iterator[int]:
    """A TLS listener on 127.0.0.1 that completes handshakes; yields its port."""
    with tempfile.TemporaryDirectory() as tmp:
        cert_file, key_file = Path(tmp, "cert.pem"), Path(tmp, "key.pem")
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        if legacy_only:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers(LEGACY_CIPHERS)
        listener = socket.socket()
        listener.bind((LOOPBACK, 0))
        listener.listen(16)
        stop = threading.Event()

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                try:
                    ctx.wrap_socket(conn, server_side=True).close()
                except (OSError, ssl.SSLError):
                    conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            yield int(listener.getsockname()[1])
        finally:
            stop.set()
            listener.close()
