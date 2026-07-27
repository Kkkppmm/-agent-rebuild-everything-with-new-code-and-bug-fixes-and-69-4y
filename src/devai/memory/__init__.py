"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
  """Stores conversation history with optional token limit."""

  def __init__(self, max_messages: int = 50) -> None:
    self.max_messages = max_messages
    self._messages: list[Message] = []

  def add(self, role: Role | str, content: str, **kwargs) -> None:
    if isinstance(role, str):
      role = Role(role)
    self._messages.append(Message(role=role, content=content, **kwargs))
    if len(self._messages) > self.max_messages:
      self._messages = self._messages[-self.max_messages:]

  def add_user(self, content: str) -> None:
    self.add(Role.USER, content)

  def add_assistant(self, content: str) -> None:
    self.add(Role.ASSISTANT, content)

  def add_system(self, content: str) -> None:
    self.add(Role.SYSTEM, content)

  def get_messages(self) -> list[Message]:
    return list(self._messages)

  def clear(self) -> None:
    self._messages.clear()

  def __len__(self) -> int:
    return len(self._messages)
