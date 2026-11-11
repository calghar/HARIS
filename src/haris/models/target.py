"""Target and scope models for defining what to scan."""

import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_EXCLUDED_PATH_CHARS = 200
_QUANTIFIER = re.compile(r"\d*(,\d*)?")


def check_excluded_paths(patterns: object) -> None:
    """Compile every pattern; reject long, invalid, or catastrophic ones."""
    if not isinstance(patterns, list):
        raise ValueError("excluded_paths must be a list of strings")
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise ValueError("excluded_paths must be a list of strings")
        if len(pattern) > MAX_EXCLUDED_PATH_CHARS:
            raise ValueError(
                f"excluded path is longer than {MAX_EXCLUDED_PATH_CHARS} characters"
            )
        if _has_nested_quantifier(pattern):
            raise ValueError(
                "excluded path pattern has nested quantifiers or quantified "
                f"alternation ({pattern})"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"excluded path pattern is not a valid regex ({pattern})"
            ) from exc


def _has_nested_quantifier(pattern: str) -> bool:
    """True when a quantifier applies to a group with alternation or a quantifier."""
    frames: list[list[bool]] = []
    index = 0
    size = len(pattern)
    while index < size:
        char = pattern[index]
        if char == "\\" and index + 1 < size:
            index += 2
            continue
        if char == "[":
            index = _skip_class(pattern, index) + 1
            continue
        if char == "(":
            frames.append([False, False])
            if index + 1 < size and pattern[index + 1] == "?":
                index += 1
        elif char == ")" and frames:
            alt, inner = frames.pop()
            if frames:
                frames[-1][0] |= alt
                frames[-1][1] |= inner
            if (alt or inner) and _quantifier_at(pattern, index + 1):
                return True
        elif char == "|" and frames:
            frames[-1][0] = True
        elif char in "+*?" and frames:
            frames[-1][1] = True
        elif char == "{":
            end = _quantifier_end(pattern, index)
            if end is not None:
                if frames:
                    frames[-1][1] = True
                index = end
        index += 1
    return False


def _quantifier_at(pattern: str, index: int) -> bool:
    if index >= len(pattern):
        return False
    char = pattern[index]
    if char in "+*?":
        return True
    return char == "{" and _quantifier_end(pattern, index) is not None


def _quantifier_end(pattern: str, start: int) -> int | None:
    end = pattern.find("}", start + 1)
    if end == -1 or end > start + 12:
        return None
    body = pattern[start + 1 : end]
    if not any(char.isdigit() for char in body):
        return None
    return end if _QUANTIFIER.fullmatch(body) else None


def _skip_class(pattern: str, start: int) -> int:
    index = start + 1
    size = len(pattern)
    if index < size and pattern[index] == "^":
        index += 1
    if index < size and pattern[index] == "]":
        index += 1
    while index < size:
        if pattern[index] == "\\" and index + 1 < size:
            index += 2
            continue
        if pattern[index] == "]":
            return index
        index += 1
    return index


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

    @field_validator("excluded_paths")
    @classmethod
    def _compile_excluded_paths(cls, patterns: list[str]) -> list[str]:
        check_excluded_paths(patterns)
        return patterns

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
