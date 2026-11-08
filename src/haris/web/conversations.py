from datetime import UTC, datetime

from ..auth.models import User
from ..models.chat import Conversation

MAX_AGE_S = 7200
MAX_COUNT = 50


class ConversationRegistry:
    """In-memory conversations; each is readable by its owner and admins."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[Conversation, str]] = {}

    def add(self, conversation: Conversation, owner_user_id: str) -> None:
        self._items[conversation.conversation_id] = (conversation, owner_user_id)

    def get(
        self, conversation_id: str, scan_id: str, user: User
    ) -> Conversation | None:
        entry = self._items.get(conversation_id)
        if entry is None:
            return None
        conversation, owner = entry
        if conversation.scan_id != scan_id:
            return None
        return conversation if user.is_admin or owner == user.user_id else None

    def exists(self, conversation_id: str) -> bool:
        return conversation_id in self._items

    def delete(self, conversation_id: str) -> None:
        self._items.pop(conversation_id, None)

    def evict_expired(self) -> None:
        now = datetime.now(UTC)
        for cid, (conv, _) in list(self._items.items()):
            age = (now - datetime.fromisoformat(conv.created_at)).total_seconds()
            if age > MAX_AGE_S:
                del self._items[cid]
        while len(self._items) > MAX_COUNT:
            oldest = min(self._items, key=lambda k: self._items[k][0].created_at)
            del self._items[oldest]
