"""Chat conversation data models for multi-turn LLM Q&A."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single message in a conversation."""

    role: str  # "user" | "assistant"
    content: str
    timestamp: str = ""
    token_count: int = 0


class Conversation(BaseModel):
    """A multi-turn conversation about a scan report."""

    conversation_id: str
    scan_id: str
    messages: list[ChatMessage] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    backend_name: str = ""
    total_tokens: int = 0

    def add_message(
        self, role: str, content: str, token_count: int = 0
    ) -> ChatMessage:
        """Append a message and update token totals."""
        msg = ChatMessage(
            role=role,
            content=content,
            timestamp=datetime.now(UTC).isoformat(),
            token_count=token_count,
        )
        self.messages.append(msg)
        self.total_tokens += token_count
        return msg

    @property
    def message_count(self) -> int:
        return len(self.messages)
