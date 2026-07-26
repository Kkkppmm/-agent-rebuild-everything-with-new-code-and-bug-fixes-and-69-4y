"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores and manages conversation message history."""

    def __init__(self, max_messages: int = 50) -> None:
        self.max_messages = max_messages
        self._messages: list[Message] = []

    def add(self, role: Role, content: str, **kwargs: object) -> None:
        self._messages.append(Message(role=role, content=content, **kwargs))  # type: ignore[arg-type]
        self._trim()

    def add_user(self, content: str) -> None:
        self.add(Role.USER, content)

    def add_assistant(self, content: str) -> None:
        self.add(Role.ASSISTANT, content)

    def add_system(self, content: str) -> None:
        self.add(Role.SYSTEM, content)

    def messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    def _trim(self) -> None:
        if len(self._messages) > self.max_messages:
            # Keep system messages and trim oldest non-system
            system = [m for m in self._messages if m.role == Role.SYSTEM]
            rest = [m for m in self._messages if m.role != Role.SYSTEM]
            overflow = len(self._messages) - self.max_messages
            rest = rest[overflow:]
            self._messages = system + rest

    def __len__(self) -> int:
        return len(self._messages)
