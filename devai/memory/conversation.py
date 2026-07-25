"""Sliding-window conversation memory."""

from __future__ import annotations

from collections import deque

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores recent messages with optional token/turn limits."""

    def __init__(self, max_messages: int = 50) -> None:
        self.max_messages = max_messages
        self._messages: deque[Message] = deque(maxlen=max_messages)

    def add(self, message: Message) -> None:
        self._messages.append(message)

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    def __len__(self) -> int:
        return len(self._messages)

    def last_user_message(self) -> Message | None:
        for msg in reversed(self._messages):
            if msg.role == Role.USER:
                return msg
        return None

    def last_assistant_message(self) -> Message | None:
        for msg in reversed(self._messages):
            if msg.role == Role.ASSISTANT:
                return msg
        return None

    def to_text(self) -> str:
        parts = []
        for msg in self._messages:
            role = msg.role.value.upper()
            content = msg.content or ""
            parts.append(f"{role}: {content}")
        return "\n".join(parts)
