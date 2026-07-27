"""Conversation memory management."""

from __future__ import annotations

from devai.core.models import Message, Role


class ConversationMemory:
  """Sliding-window conversation memory for multi-turn interactions."""

  def __init__(self, max_messages: int = 20, system_prompt: str | None = None) -> None:
    self.max_messages = max_messages
    self._messages: list[Message] = []
    if system_prompt:
      self._messages.append(Message(role=Role.SYSTEM, content=system_prompt))

  def add_user(self, content: str) -> None:
    self._messages.append(Message(role=Role.USER, content=content))
    self._trim()

  def add_assistant(self, content: str) -> None:
    self._messages.append(Message(role=Role.ASSISTANT, content=content))
    self._trim()

  def add(self, message: Message) -> None:
    self._messages.append(message)
    self._trim()

  def get_messages(self) -> list[Message]:
    return list(self._messages)

  def clear(self) -> None:
    system = [m for m in self._messages if m.role == Role.SYSTEM]
    self._messages = system

  def _trim(self) -> None:
    system = [m for m in self._messages if m.role == Role.SYSTEM]
    non_system = [m for m in self._messages if m.role != Role.SYSTEM]
    if len(non_system) > self.max_messages:
      non_system = non_system[-self.max_messages :]
    self._messages = system + non_system

  def __len__(self) -> int:
    return len(self._messages)
