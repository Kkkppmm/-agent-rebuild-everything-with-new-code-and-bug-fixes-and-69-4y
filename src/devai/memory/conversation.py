"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores and manages conversation history with optional windowing."""

    def __init__(self, max_messages: int | None = None) -> None:
        self.messages: list[Message] = []
        self.max_messages = max_messages

    def add(self, role: Role | str, content: str) -> None:
        if isinstance(role, str):
            role = Role(role)
        self.messages.append(Message(role=role, content=content))
        self._trim()

    def add_user(self, content: str) -> None:
        self.add(Role.USER, content)

    def add_assistant(self, content: str) -> None:
        self.add(Role.ASSISTANT, content)

    def add_system(self, content: str) -> None:
        self.add(Role.SYSTEM, content)

    def get_messages(self) -> list[Message]:
        return list(self.messages)

    def clear(self) -> None:
        self.messages = []

    def _trim(self) -> None:
        if self.max_messages and len(self.messages) > self.max_messages:
            system = [m for m in self.messages if m.role == Role.SYSTEM]
            rest = [m for m in self.messages if m.role != Role.SYSTEM]
            keep = rest[-(self.max_messages - len(system)) :]
            self.messages = system + keep

    def __len__(self) -> int:
        return len(self.messages)

    def __repr__(self) -> str:
        return f"ConversationMemory({len(self)} messages)"
