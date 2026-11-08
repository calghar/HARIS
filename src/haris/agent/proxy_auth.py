import base64
import hashlib
import hmac
import secrets

PROXY_USER = "job"


def new_proxy_token() -> str:
    """32 random bytes, URL-safe, with no colon or at-sign."""
    return secrets.token_urlsafe(32)


def client_proxy_url(token: str, netloc: str) -> str:
    return f"http://{PROXY_USER}:{token}@{netloc}"


def authorized(header: str, token: str) -> bool:
    """Constant-time check of Proxy-Authorization Basic base64(job:token)."""
    expected = base64.b64encode(f"{PROXY_USER}:{token}".encode())
    scheme, _, rest = header.strip().partition(" ")
    presented = rest.encode() if scheme.lower() == "basic" else b""
    return hmac.compare_digest(
        hashlib.sha256(presented).digest(),
        hashlib.sha256(expected).digest(),
    )
