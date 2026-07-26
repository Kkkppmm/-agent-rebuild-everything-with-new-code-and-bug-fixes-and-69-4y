"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message
from devai.utils.tokens import estimate_tokens, truncate_to_tokens


class ConversationMemory:
    """Stores and manages conversation history with token-aware truncation."""

    def __init__(self, max_tokens: int = 8000, system_message: str | None = None):
        self.max_tokens = max_tokens
        self._messages: list[Message] = []
        if system_message:
            self._messages.append(Message(role="system", content=system_message))

    def add_user(self, content: str) -> None:
        self._messages.append(Message(role="user", content=content))

    def add_assistant(self, content: str) -> None:
        self._messages.append(Message(role="assistant", content=content))

    def add(self, message: Message) -> None:
        self._messages.append(message)

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def get_context(self) -> list[Message]:
        """Return messages truncated to fit within max_tokens."""
        if not self._messages:
            return []

        total = sum(estimate_tokens(m.content or "") for m in self._messages)
        if total <= self.max_tokens:
            return list(self._messages)

        # Keep system message and truncate from the middle
        system = [m for m in self._messages if m.role == "system"]
        rest = [m for m in self._messages if m.role != "system"]

        while rest and sum(estimate_tokens(m.content or "") for m in system + rest) > self.max_tokens:
            rest.pop(0)

        return system + rest

    def clear(self) -> None:
        system = [m for m in self._messages if m.role == "system"]
        self._messages = system

    def __len__(self) -> int:
        return len(self._messages)

    @property
    def token_count(self) -> int:
        return sum(estimate_tokens(m.content or "") for m in self._messages)
