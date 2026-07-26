"""Conversation memory for DevAI."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores conversation history with optional windowing."""

    def __init__(self, max_messages: int | None = None, system_prompt: str | None = None):
        self.max_messages = max_messages
        self._messages: list[Message] = []
        if system_prompt:
            self._messages.append(Message.system(system_prompt))

    def add(self, message: Message) -> None:
        self._messages.append(message)
        self._trim()

    def add_user(self, content: str) -> None:
        self.add(Message.user(content))

    def add_assistant(self, content: str) -> None:
        self.add(Message.assistant(content))

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        system = [m for m in self._messages if m.role == Role.SYSTEM]
        self._messages = system

    def _trim(self) -> None:
        if self.max_messages is None:
            return
        system = [m for m in self._messages if m.role == Role.SYSTEM]
        rest = [m for m in self._messages if m.role != Role.SYSTEM]
        if len(rest) > self.max_messages:
            rest = rest[-self.max_messages :]
        self._messages = system + rest

    def __len__(self) -> int:
        return len(self._messages)
