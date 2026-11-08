import socket

import pytest

PUBLIC_ADDRESS = "93.184.216.34"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every hostname to a public address so no test touches real DNS."""
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        if host in ("localhost", "127.0.0.1", "::1", "testserver"):
            return real(host, port, *args, **kwargs)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port or 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.fixture(autouse=True)
def fast_bcrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimum bcrypt cost keeps user creation in tests cheap."""
    import bcrypt

    real = bcrypt.gensalt
    monkeypatch.setattr(bcrypt, "gensalt", lambda *_a, **_k: real(rounds=4))
