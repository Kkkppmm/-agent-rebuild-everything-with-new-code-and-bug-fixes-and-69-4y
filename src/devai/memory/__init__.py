"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores and manages conversation history."""

    def __init__(self, max_messages: int = 50):
        self.max_messages = max_messages
        self._messages: list[Message] = []

    @property
    def messages(self) -> list[Message]:
        return list(self._messages)

    def add(self, role: Role | str, content: str, **kwargs) -> None:
        self._messages.append(Message(role=role, content=content, **kwargs))
        self._trim()

    def add_user(self, content: str) -> None:
        self.add(Role.USER, content)

    def add_assistant(self, content: str) -> None:
        self.add(Role.ASSISTANT, content)

    def add_system(self, content: str) -> None:
        self.add(Role.SYSTEM, content)

    def clear(self) -> None:
        self._messages.clear()

    def get_messages(self, include_system: bool = True) -> list[Message]:
        if include_system:
            return list(self._messages)
        return [m for m in self._messages if m.role != Role.SYSTEM]

    def _trim(self) -> None:
        if len(self._messages) > self.max_messages:
            system_msgs = [m for m in self._messages if m.role == Role.SYSTEM]
            other_msgs = [m for m in self._messages if m.role != Role.SYSTEM]
            keep = self.max_messages - len(system_msgs)
            self._messages = system_msgs + other_msgs[-keep:]

    def __len__(self) -> int:
        return len(self._messages)

    def __repr__(self) -> str:
        return f"ConversationMemory(messages={len(self._messages)})"
