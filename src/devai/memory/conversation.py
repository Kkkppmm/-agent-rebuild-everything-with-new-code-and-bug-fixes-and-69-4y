"""Conversation memory for DevAI."""

from __future__ import annotations

from devai.core.models import Message, Role
from devai.utils import estimate_tokens


class ConversationMemory:
    """Store and manage conversation history with token limits."""

    def __init__(self, max_tokens: int = 8000, system_message: str | None = None) -> None:
        self.max_tokens = max_tokens
        self.messages: list[Message] = []
        if system_message:
            self.messages.append(Message.system(system_message))

    def add(self, message: Message) -> None:
        self.messages.append(message)
        self._trim()

    def add_user(self, content: str) -> None:
        self.add(Message.user(content))

    def add_assistant(self, content: str) -> None:
        self.add(Message.assistant(content))

    def get_messages(self) -> list[Message]:
        return list(self.messages)

    def clear(self) -> None:
        system = [m for m in self.messages if m.role == Role.SYSTEM]
        self.messages = system

    def _trim(self) -> None:
        total = sum(estimate_tokens(m.content) for m in self.messages)
        while total > self.max_tokens and len(self.messages) > 1:
            # Keep system messages, remove oldest non-system
            for i, msg in enumerate(self.messages):
                if msg.role != Role.SYSTEM:
                    removed = self.messages.pop(i)
                    total -= estimate_tokens(removed.content)
                    break
            else:
                break

    @property
    def token_count(self) -> int:
        return sum(estimate_tokens(m.content) for m in self.messages)

    def __len__(self) -> int:
        return len(self.messages)
