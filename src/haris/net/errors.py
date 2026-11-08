class NetworkError(Exception):
    """Base for every error raised by the scoped HTTP client."""


class ScopeViolation(NetworkError):  # noqa: N818 - names fixed by the spec
    """Scheme, URL or method is outside the authorised scope."""


class SSRFBlocked(NetworkError):  # noqa: N818 - names fixed by the spec
    """The host resolves to an address the SSRF guard blocks."""


class RequestBudgetExceeded(NetworkError):  # noqa: N818 - names fixed by the spec
    """The request would exceed ``Scope.max_requests``."""


class TransportError(NetworkError):
    """Connection failure after retries were exhausted."""
