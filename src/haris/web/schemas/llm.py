from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BackendStatus(BaseModel):
    name: str
    available: bool
    reason: str = ""
    model: str = ""
    endpoint: str = ""


class BackendList(BaseModel):
    backends: list[BackendStatus]
    default: str


class Answer(BaseModel):
    answer: str
    model: str
    tokens: int


class ChatAnswer(Answer):
    conversation_id: str
    message_count: int
    total_tokens: int


class ChatMessageOut(BaseModel):
    role: str
    content: str
    timestamp: str = ""
    token_count: int = 0


class ConversationOut(BaseModel):
    conversation_id: str
    messages: list[ChatMessageOut]
    total_tokens: int


class ConversationSummary(BaseModel):
    conversation_id: str
    scan_id: str
    backend_name: str
    created_at: str
    message_count: int
    total_tokens: int


class ConversationDeleted(BaseModel):
    deleted: str


class Enrichment(BaseModel):
    enrichments: dict[str, dict[str, Any]]
    attack_chains: list[dict[str, Any]]
    triaged_findings: list[dict[str, Any]]
    has_enrichment: bool


class ScanQuery(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    scan_id: str = Field(min_length=1)
    backend: str | None = None


class AskIn(ScanQuery):
    question: str = Field(min_length=1)


class ChatIn(AskIn):
    conversation_id: str | None = None


class SummarizeIn(ScanQuery):
    audience: str = "executive"


class ExplainIn(ScanQuery):
    finding_id: str = Field(min_length=1)


class RemediationIn(ScanQuery):
    format: str = "markdown"


class TestCasesIn(ScanQuery):
    __test__ = False
    framework: str = "generic"


class MitigationsIn(ScanQuery):
    stack: str = "generic web"


class FilterIn(ScanQuery):
    criteria: str = Field(min_length=1)
