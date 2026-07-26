"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
    """Stores and manages conversation history with optional windowing."""

    def __init__(self, *, max_messages: int = 50, system_prompt: str | None = None) -> None:
        self.max_messages = max_messages
        self._messages: list[Message] = []
        if system_prompt:
            self._messages.append(Message(role=Role.SYSTEM, content=system_prompt))

    def add(self, role: Role | str, content: str, **kwargs) -> Message:
        if isinstance(role, str):
            role = Role(role)
        msg = Message(role=role, content=content, **kwargs)
        self._messages.append(msg)
        self._trim()
        return msg

    def add_user(self, content: str) -> Message:
        return self.add(Role.USER, content)

    def add_assistant(self, content: str) -> Message:
        return self.add(Role.ASSISTANT, content)

    def get_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self, *, keep_system: bool = True) -> None:
        if keep_system and self._messages and self._messages[0].role == Role.SYSTEM:
            self._messages = [self._messages[0]]
        else:
            self._messages = []

    def _trim(self) -> None:
        system_msgs = [m for m in self._messages if m.role == Role.SYSTEM]
        other_msgs = [m for m in self._messages if m.role != Role.SYSTEM]
        if len(other_msgs) > self.max_messages:
            other_msgs = other_msgs[-self.max_messages :]
        self._messages = system_msgs + other_msgs

    def __len__(self) -> int:
        return len(self._messages)

    def __repr__(self) -> str:
        return f"ConversationMemory(messages={len(self._messages)})"
