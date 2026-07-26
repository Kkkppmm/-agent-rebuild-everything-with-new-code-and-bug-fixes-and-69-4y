"""Conversation memory management."""

from __future__ import annotations

from devai.core.models import Message, Role
from devai.utils.tokens import estimate_tokens, truncate_to_tokens


class ConversationMemory:
    """Sliding-window conversation memory with token limits."""

    def __init__(self, max_tokens: int = 8000, system_prompt: str | None = None) -> None:
        self.max_tokens = max_tokens
        self.messages: list[Message] = []
        if system_prompt:
            self.messages.append(Message(role=Role.SYSTEM, content=system_prompt))

    def add(self, role: Role, content: str) -> None:
        self.messages.append(Message(role=role, content=content))
        self._trim()

    def add_message(self, message: Message) -> None:
        self.messages.append(message)
        self._trim()

    def get_messages(self) -> list[Message]:
        return list(self.messages)

    def clear(self) -> None:
        system = [m for m in self.messages if m.role == Role.SYSTEM]
        self.messages = system

    def _trim(self) -> None:
        total = sum(estimate_tokens(m.content) for m in self.messages)
        while total > self.max_tokens and len(self.messages) > 1:
            # Keep system messages, trim oldest non-system
            for i, msg in enumerate(self.messages):
                if msg.role != Role.SYSTEM:
                    total -= estimate_tokens(msg.content)
                    self.messages.pop(i)
                    break
            else:
                break

    @property
    def token_count(self) -> int:
        return sum(estimate_tokens(m.content) for m in self.messages)

    def __len__(self) -> int:
        return len(self.messages)
