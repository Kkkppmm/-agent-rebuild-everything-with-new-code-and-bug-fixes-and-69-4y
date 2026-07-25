"""Conversation memory management."""

from __future__ import annotations

from collections import deque

from devai.core.models import Message, Role


class ConversationMemory:
  """Rolling window conversation history."""

  def __init__(self, *, max_messages: int = 50, system: str | None = None) -> None:
    self.max_messages = max_messages
    self._messages: deque[Message] = deque(maxlen=max_messages)
    if system:
      self._system = Message(role=Role.SYSTEM, content=system)
    else:
      self._system = None

  def add(self, role: Role | str, content: str) -> None:
    """Append a message to memory."""
    if isinstance(role, str):
      role = Role(role)
    self._messages.append(Message(role=role, content=content))

  def add_message(self, message: Message) -> None:
    """Append a full message object."""
    self._messages.append(message)

  def messages(self) -> list[Message]:
    """Return all messages including optional system prompt."""
    result: list[Message] = []
    if self._system:
      result.append(self._system)
    result.extend(self._messages)
    return result

  def clear(self) -> None:
    """Remove conversation history (keeps system prompt)."""
    self._messages.clear()

  def __len__(self) -> int:
    return len(self._messages)

  def __repr__(self) -> str:
    return f"ConversationMemory(messages={len(self._messages)}, max={self.max_messages})"
