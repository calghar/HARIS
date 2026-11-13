from ..llm.redaction import DATA_CLAUSE, fence, new_nonce, redact
from ..models import EvidenceExchange, Finding
from .settings import LLMVerdictSettings

MAX_SPAN_CHARS = 300
MAX_RATIONALE_CHARS = 2000

TASK = (
    "You judge whether one security scanner finding is real, using only the "
    "request/response exchanges provided. Reply with one JSON object: "
    "case_id (echo the given id), verdict (confirmed | likely_fp | inconclusive), "
    "confidence (0 to 1), cited_spans (1 to 5 objects {exchange_index, text}, each "
    f"text one unbroken run of at most {MAX_SPAN_CHARS} characters copied exactly "
    "from that exchange; never join parts with '...' and never skip lines, use one "
    'span per part, for example {"exchange_index": 0, "text": "HTTP 200 (4 ms)"}), '
    f"rationale (at most {MAX_RATIONALE_CHARS} characters). "
    "Answer inconclusive when the exchanges do not decide."
)
SYSTEM = f"{DATA_CLAUSE}\n{TASK}"


def exchange_text(exchange: EvidenceExchange, cfg: LLMVerdictSettings) -> str:
    """The redacted text of one exchange; cited spans must be substrings of it."""
    allowed = {h.lower() for h in cfg.response_headers}
    request = "\n".join(
        [
            f"{exchange.method} {exchange.url}",
            *(f"{k}: {v}" for k, v in exchange.request_headers.items()),
            "",
            exchange.request_body_excerpt,
        ]
    )[: cfg.request_chars]
    response = "\n".join(
        [
            f"HTTP {exchange.status} ({exchange.elapsed_ms:.0f} ms)",
            *(
                f"{k}: {v}"
                for k, v in exchange.response_headers.items()
                if k.lower() in allowed
            ),
            "",
            exchange.response_body_excerpt,
        ]
    )
    return redact(f"{request}\n\n{response}".replace("\r\n", "\n"))


def finding_text(finding: Finding) -> str:
    verification = finding.verification
    return redact(
        "\n".join(
            [
                f"title: {finding.title}",
                f"class: {finding.vuln_class}",
                f"cwe: {finding.cwe_id}",
                f"severity: {finding.severity.value}",
                f"url: {finding.url}",
                f"method: {finding.method}",
                f"parameter: {finding.parameter}",
                f"scanners: {finding.scanner}",
                f"oracle: {verification.oracle.value}, outcome: inconclusive",
            ]
        )
    )


def build_prompt(case_id: str, finding: Finding, texts: list[str]) -> str:
    """Case prompt; the finding and every exchange sit inside one nonce fence each."""
    nonce = new_nonce()
    while any(nonce in text for text in [finding_text(finding), *texts]):
        nonce = new_nonce()
    parts = [f"Case id: {case_id}", "Finding:", fence(finding_text(finding), nonce)]
    for index, (text, exchange) in enumerate(
        zip(texts, finding.verification.evidence, strict=True)
    ):
        parts += [f"Exchange {index} ({exchange.role}):", fence(text, nonce)]
    return "\n".join(parts)
