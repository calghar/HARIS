import secrets
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from ..models import EvidenceExchange, Finding
from ..net import ScopedClient, ScopedResponse
from . import evidence

FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


class NotReplayable(Exception):  # noqa: N818 - a skip reason, not a failure
    """The finding does not carry enough to rebuild its request."""


class VerifyBudgetExhausted(Exception):  # noqa: N818 - control flow, not a failure
    """``verify.max_requests`` is spent."""


def random_token(length: int) -> str:
    """Alphanumeric control value of the same length as the probe payload."""
    return secrets.token_hex(length // 2 + 1)[:length]


def build_request(
    finding: Finding, base_url: str, value: str
) -> tuple[str, str, bytes | None, dict[str, str]]:
    """The finding's own request with its parameter set to *value*."""
    if not finding.parameter:
        raise NotReplayable("finding has no parameter to replay")
    method = finding.method.upper()
    url = urljoin(f"{base_url}/", finding.url)
    if method == "POST":
        body = urlencode({finding.parameter: value}).encode()
        return method, url, body, dict(FORM_HEADERS)
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    swapped = [(k, value if k == finding.parameter else v) for k, v in pairs]
    if finding.parameter not in {k for k, _ in pairs}:
        swapped.append((finding.parameter, value))
    query = urlencode(swapped, quote_via=quote)
    return method, urlunsplit(parts._replace(query=query)), None, {}


class Prober:
    """Sends replay requests through the scan's ScopedClient within a request cap."""

    def __init__(
        self, client: ScopedClient, limit: int, timeout_s: float | None = None
    ) -> None:
        self.client = client
        self._limit = limit
        self._timeout_s = timeout_s
        self._start = client.requests_sent

    @property
    def timeout_s(self) -> float | None:
        return self._timeout_s

    @property
    def used(self) -> int:
        return self.client.requests_sent - self._start

    def send(
        self, finding: Finding, value: str, *, follow_redirects: bool = True
    ) -> ScopedResponse:
        """The finding's request with its parameter set to *value*."""
        method, url, body, headers = build_request(
            finding, self.client.target.base_url, value
        )
        return self.request(
            method, url, body=body, headers=headers, follow_redirects=follow_redirects
        )

    def get(self, finding: Finding) -> ScopedResponse:
        return self.request(
            "GET", urljoin(f"{self.client.target.base_url}/", finding.url)
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> ScopedResponse:
        if self.used >= self._limit:
            raise VerifyBudgetExhausted(f"verify.max_requests={self._limit} reached")
        return self.client.request(
            method,
            url,
            headers=headers,
            body=body,
            timeout_s=self._timeout_s,
            follow_redirects=follow_redirects,
        )

    def exchange(
        self, response: ScopedResponse, role: str, span: str = ""
    ) -> EvidenceExchange:
        return evidence.exchange(self.client, response, role, span)
