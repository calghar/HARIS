import re
from collections.abc import Callable

from haris.llm.backend import LLMRequest, ProviderBackend
from haris.models import Confidence, Finding, Severity
from haris.models.llm import LLMResponse

Handler = Callable[[LLMRequest], str]

FENCE = re.compile(
    r'<untrusted-data id="(\w+)">\n(.*?)\n</untrusted-data id="\1">', re.DOTALL
)


def make_finding(
    finding_id: str = "F001",
    *,
    severity: Severity = Severity.HIGH,
    title: str = "Reflected XSS in search",
    evidence: str = "<script>alert(1)</script> reflected in q",
) -> Finding:
    return Finding(
        title=title,
        description="User input is echoed without encoding.",
        severity=severity,
        confidence=Confidence.TENTATIVE,
        url="https://example.com/search?q=x",
        scanner="wapiti",
        tags=["xss"],
        finding_id=finding_id,
        evidence=evidence,
    )


def fenced_blocks(text: str) -> list[str]:
    return [m.group(2) for m in FENCE.finditer(text)]


def prompt_ids(request: LLMRequest) -> list[str]:
    """Finding IDs listed as `- [ID]` in the user prompt."""
    return re.findall(r"^- \[(\w+)\]", request.messages[-1]["content"], re.MULTILINE)


class FakeClock:
    def __init__(self) -> None:
        self.slept: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)


class FakeProvider(ProviderBackend):
    """Offline provider: records every request that reaches the wire."""

    name = "fake"
    model = "fake-model"
    cache = None

    def __init__(
        self,
        handler: Handler,
        *,
        tokens_per_call: int = 100,
        clock: FakeClock | None = None,
    ) -> None:
        self._handler = handler
        self._tokens = tokens_per_call
        self.requests: list[LLMRequest] = []
        if clock is not None:
            self.sleep = clock.sleep

    def _send(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        text = self._handler(request)
        half = self._tokens // 2
        return LLMResponse(
            text=text,
            model=self.model,
            usage={
                "prompt_tokens": half,
                "completion_tokens": self._tokens - half,
                "total_tokens": self._tokens,
            },
        )

    @property
    def wire_text(self) -> str:
        return "\n".join(
            [
                r.system + "\n" + "\n".join(m["content"] for m in r.messages)
                for r in self.requests
            ]
        )
