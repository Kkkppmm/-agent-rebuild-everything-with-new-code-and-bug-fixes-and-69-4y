"""Conversation memory for multi-turn interactions."""

from __future__ import annotations

from devai.core.models import Message, Role
from devai.utils.tokens import estimate_tokens


class ConversationMemory:
  """Stores and manages conversation history with optional token limits."""

  def __init__(self, max_messages: int = 50, max_tokens: int | None = None) -> None:
    self.max_messages = max_messages
    self.max_tokens = max_tokens
    self._messages: list[Message] = []

  def add(self, message: Message) -> None:
    """Append a message and enforce limits."""
    self._messages.append(message)
    self._trim()

  def add_user(self, content: str) -> None:
    self.add(Message.user(content))

  def add_assistant(self, content: str) -> None:
    self.add(Message.assistant(content))

  def add_system(self, content: str) -> None:
    self.add(Message.system(content))

  def get_messages(self) -> list[Message]:
    return list(self._messages)

  def clear(self) -> None:
    self._messages.clear()

  @property
  def messages(self) -> list[Message]:
    return self.get_messages()

  def _trim(self) -> None:
    if len(self._messages) > self.max_messages:
      system_msgs = [m for m in self._messages if m.role == Role.SYSTEM]
      other = [m for m in self._messages if m.role != Role.SYSTEM]
      keep = other[-(self.max_messages - len(system_msgs)) :]
      self._messages = system_msgs + keep

    if self.max_tokens is not None:
      while self._total_tokens() > self.max_tokens and len(self._messages) > 1:
        for i, msg in enumerate(self._messages):
          if msg.role != Role.SYSTEM:
            self._messages.pop(i)
            break
        else:
          break

  def _total_tokens(self) -> int:
    return sum(estimate_tokens(m.content) for m in self._messages)

  def __len__(self) -> int:
    return len(self._messages)
