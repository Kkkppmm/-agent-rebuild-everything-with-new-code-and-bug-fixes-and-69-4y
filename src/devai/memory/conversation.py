"""Conversation memory for agents and chains."""

from __future__ import annotations

from dataclasses import dataclass, field

from devai.core.messages import Message


@dataclass
class ConversationMemory:
    """Stores conversation history with optional windowing."""

    messages: list[Message] = field(default_factory=list)
    max_messages: int | None = None

    def add(self, message: Message) -> None:
        self.messages.append(message)
        if self.max_messages and len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages :]

    def get_messages(self) -> list[Message]:
        return list(self.messages)

    def clear(self) -> None:
        self.messages.clear()

    def __len__(self) -> int:
        return len(self.messages)

    @property
    def last(self) -> Message | None:
        return self.messages[-1] if self.messages else None
