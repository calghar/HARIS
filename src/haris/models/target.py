"""Target and scope models for defining what to scan."""

import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator


class Scope(BaseModel):
    """Defines the authorized testing boundaries.

    All scanners MUST consult the scope before sending requests
    to ensure testing stays within the authorized perimeter.
    """

    allowed_domains: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    max_depth: int = 5
    rate_limit_rps: float = 10.0
    max_requests: int = 10_000
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "HEAD", "OPTIONS"]
    )
    follow_redirects: bool = True
    max_redirect_depth: int = 5

    def is_url_in_scope(self, url: str) -> bool:
        """Check whether *url* falls within the allowed scope."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check domain allowlist
        if self.allowed_domains and not any(
            hostname == d or hostname.endswith(f".{d}") for d in self.allowed_domains
        ):
            return False

        # Check excluded paths
        path = parsed.path
        return all(not re.search(pattern, path) for pattern in self.excluded_paths)


class AuthConfig(BaseModel):
    """Optional authentication configuration for the target.

    Supports cookie-based, header-based (Bearer token), or
    form-based auth. Credentials should be supplied via
    environment variables, not hardcoded.
    """

    method: str = "none"  # none | cookie | header | form
    cookie_name: str = ""
    cookie_value: str = ""  # set via env var
    header_name: str = "Authorization"
    header_value: str = ""  # set via env var
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username: str = ""  # set via env var
    password: str = ""  # set via env var

    def as_headers(self) -> dict[str, str]:
        """Return auth-related HTTP headers."""
        headers: dict[str, str] = {}
        if self.method == "header" and self.header_value:
            headers[self.header_name] = self.header_value
        elif self.method == "cookie" and self.cookie_value:
            headers["Cookie"] = f"{self.cookie_name}={self.cookie_value}"
        return headers

    def __repr__(self) -> str:
        """Redact secrets to prevent credential leakage in logs."""
        return (
            f"AuthConfig(method={self.method!r}, "
            f"header_name={self.header_name!r}, "
            f"login_url={self.login_url!r}, "
            f"credentials=<REDACTED>)"
        )


class Target(BaseModel):
    """Represents the website to be audited.

    Attributes:
        base_url: The root URL of the target application.
        scope: Authorized testing boundaries.
        auth: Optional authentication configuration.
        metadata: Arbitrary key-value pairs.
    """

    base_url: str
    scope: Scope = Field(default_factory=Scope)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_url(self) -> "Target":
        """Normalise URL and auto-populate scope."""
        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = f"https://{self.base_url}"
        self.base_url = self.base_url.rstrip("/")

        # Auto-populate allowed_domains from base_url if empty
        if not self.scope.allowed_domains:
            parsed = urlparse(self.base_url)
            if parsed.hostname:
                self.scope.allowed_domains = [parsed.hostname]
        return self

    @property
    def hostname(self) -> str:
        return urlparse(self.base_url).hostname or ""

    @property
    def port(self) -> int:
        parsed = urlparse(self.base_url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @property
    def scheme(self) -> str:
        return urlparse(self.base_url).scheme
