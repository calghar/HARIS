from __future__ import annotations

import pytest

from src.models.chat import ChatMessage, Conversation


class TestChatMessageDefaults:
    def test_chat_message_defaults(self):
        """timestamp defaults to empty string and token_count defaults to 0."""
        msg = ChatMessage(role="user", content="Hello")

        assert msg.timestamp == ""
        assert msg.token_count == 0

    def test_chat_message_explicit_values(self):
        """Explicit values for optional fields are stored as provided."""
        msg = ChatMessage(
            role="assistant",
            content="Hi there",
            timestamp="2025-01-01T00:00:00+00:00",
            token_count=42,
        )

        assert msg.role == "assistant"
        assert msg.content == "Hi there"
        assert msg.timestamp == "2025-01-01T00:00:00+00:00"
        assert msg.token_count == 42

    def test_chat_message_role_and_content_required(self):
        """Omitting role or content raises a Pydantic ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ChatMessage(content="no role")  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ChatMessage(role="user")  # type: ignore[call-arg]


class TestConversationAddMessage:
    def _make_conversation(self) -> Conversation:
        return Conversation(conversation_id="conv-1", scan_id="scan-1")

    def test_conversation_add_message_correct_role_and_content(self):
        """add_message creates a ChatMessage with the supplied role and content."""
        conv = self._make_conversation()

        msg = conv.add_message("user", "What are the risks?")

        assert msg.role == "user"
        assert msg.content == "What are the risks?"

    def test_conversation_add_message_appended_to_messages(self):
        """The returned ChatMessage is appended to the messages list."""
        conv = self._make_conversation()

        returned = conv.add_message("assistant", "Here is the summary.")

        assert len(conv.messages) == 1
        assert conv.messages[0] is returned

    def test_conversation_add_message_sets_timestamp(self):
        """add_message always sets a non-empty ISO timestamp."""
        conv = self._make_conversation()

        msg = conv.add_message("user", "ping")

        assert msg.timestamp != ""

    def test_conversation_add_message_token_count_default_zero(self):
        """Without explicit token_count, the ChatMessage has token_count == 0."""
        conv = self._make_conversation()

        msg = conv.add_message("user", "no tokens")

        assert msg.token_count == 0

    def test_conversation_add_message_stores_token_count(self):
        """Explicit token_count is stored on the created message."""
        conv = self._make_conversation()

        msg = conv.add_message("assistant", "response", token_count=99)

        assert msg.token_count == 99

    def test_conversation_multiple_messages_order_preserved(self):
        """Messages are appended in insertion order."""
        conv = self._make_conversation()

        conv.add_message("user", "first")
        conv.add_message("assistant", "second")
        conv.add_message("user", "third")

        assert [m.content for m in conv.messages] == ["first", "second", "third"]


class TestConversationTotalTokens:
    def test_conversation_total_tokens_starts_at_zero(self):
        """A fresh Conversation has total_tokens == 0."""
        conv = Conversation(conversation_id="c", scan_id="s")

        assert conv.total_tokens == 0

    def test_conversation_total_tokens_sums_across_messages(self):
        """total_tokens accumulates the token_count of every added message."""
        conv = Conversation(conversation_id="c", scan_id="s")

        conv.add_message("user", "hello", token_count=10)
        conv.add_message("assistant", "hi", token_count=25)
        conv.add_message("user", "thanks", token_count=5)

        assert conv.total_tokens == 40

    def test_conversation_total_tokens_with_zero_count_messages(self):
        """Messages with token_count=0 do not alter total_tokens."""
        conv = Conversation(conversation_id="c", scan_id="s")

        conv.add_message("user", "no tokens")
        conv.add_message("assistant", "still no tokens")

        assert conv.total_tokens == 0

    def test_conversation_total_tokens_mixed(self):
        """Mixed zero and non-zero token counts sum correctly."""
        conv = Conversation(conversation_id="c", scan_id="s")

        conv.add_message("user", "q", token_count=0)
        conv.add_message("assistant", "a", token_count=50)
        conv.add_message("user", "q2", token_count=0)
        conv.add_message("assistant", "a2", token_count=75)

        assert conv.total_tokens == 125


class TestConversationMessageCount:
    def test_conversation_message_count_empty(self):
        """message_count is 0 for a new conversation."""
        conv = Conversation(conversation_id="c", scan_id="s")

        assert conv.message_count == 0

    def test_conversation_message_count_reflects_len(self):
        """message_count returns the number of messages added."""
        conv = Conversation(conversation_id="c", scan_id="s")

        conv.add_message("user", "one")
        assert conv.message_count == 1

        conv.add_message("assistant", "two")
        assert conv.message_count == 2

        conv.add_message("user", "three")
        assert conv.message_count == 3

    def test_conversation_message_count_matches_messages_len(self):
        """message_count is always equal to len(conversation.messages)."""
        conv = Conversation(conversation_id="c", scan_id="s")

        for i in range(5):
            conv.add_message("user", f"msg {i}")

        assert conv.message_count == len(conv.messages)
