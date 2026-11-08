from ..llm.redaction import redact
from ..models import EvidenceExchange
from ..models.verification import EXCERPT_LIMIT
from ..net import ScopedClient, ScopedResponse, redact_headers


def centre(body: str, span: str, limit: int = EXCERPT_LIMIT) -> str:
    """At most *limit* characters of *body*, centred on *span* when it is found."""
    index = body.find(span) if span else -1
    if len(body) <= limit or index < 0:
        return body[:limit]
    start = max(0, index - (limit - len(span)) // 2)
    return body[start : start + limit]


def exchange(
    client: ScopedClient, response: ScopedResponse, role: str, span: str = ""
) -> EvidenceExchange:
    """Redacted evidence for one response; ``request_id`` ties it to the request log."""
    entry = client.log.get(response.request_id)
    if entry is not None:
        evidence = entry.to_exchange(role)
    else:
        evidence = EvidenceExchange.model_validate(
            {
                "request_id": response.request_id,
                "role": role,
                "url": response.url,
                "status": response.status_code,
                "response_headers": redact_headers(dict(response.headers)),
                "elapsed_ms": response.elapsed_ms,
            }
        )
    return evidence.model_copy(
        update={
            "request_body_excerpt": redact(evidence.request_body_excerpt),
            "response_body_excerpt": redact(centre(response.text, span))[
                :EXCERPT_LIMIT
            ],
        }
    )
