"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores and manages conversation history with optional windowing."""

    def __init__(self, max_messages: int = 50) -> None:
        self.max_messages = max_messages
        self._messages: list[Message] = []

    @property
    def messages(self) -> list[Message]:
        return list(self._messages)

    def add(self, message: Message) -> None:
        self._messages.append(message)
        if len(self._messages) > self.max_messages:
            self._messages = self._messages[-self.max_messages :]

    def add_user(self, content: str) -> None:
        self.add(Message(role=Role.USER, content=content))

    def add_assistant(self, content: str) -> None:
        self.add(Message(role=Role.ASSISTANT, content=content))

    def add_system(self, content: str) -> None:
        self.add(Message(role=Role.SYSTEM, content=content))

    def clear(self) -> None:
        self._messages.clear()

    def get_context(self, include_system: bool = True) -> list[Message]:
        if include_system:
            return list(self._messages)
        return [m for m in self._messages if m.role != Role.SYSTEM]

    def __len__(self) -> int:
        return len(self._messages)
