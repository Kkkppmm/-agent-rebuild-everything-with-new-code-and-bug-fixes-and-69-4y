"""Conversation memory management."""

from __future__ import annotations

from abc import ABC, abstractmethod

from devai.types import Message, Role


class Memory(ABC):
  """Abstract conversation memory."""

  @abstractmethod
  def add(self, message: Message) -> None:
    ...

  @abstractmethod
  def get_messages(self) -> list[Message]:
    ...

  @abstractmethod
  def clear(self) -> None:
    ...

  def __len__(self) -> int:
    return len(self.get_messages())


class BufferMemory(Memory):
  """Stores all messages in a simple buffer."""

  def __init__(self, system_prompt: str | None = None) -> None:
    self._messages: list[Message] = []
    if system_prompt:
      self._messages.append(Message(role=Role.SYSTEM, content=system_prompt))

  def add(self, message: Message) -> None:
    self._messages.append(message)

  def get_messages(self) -> list[Message]:
    return list(self._messages)

  def clear(self) -> None:
    self._messages.clear()


class WindowMemory(Memory):
  """Keeps only the last N messages (plus any system prompt)."""

  def __init__(self, max_messages: int = 20, system_prompt: str | None = None) -> None:
    self.max_messages = max_messages
    self._system: Message | None = None
    if system_prompt:
      self._system = Message(role=Role.SYSTEM, content=system_prompt)
    self._messages: list[Message] = []

  def add(self, message: Message) -> None:
    if str(message.role) == Role.SYSTEM:
      self._system = message
      return
    self._messages.append(message)
    if len(self._messages) > self.max_messages:
      self._messages = self._messages[-self.max_messages:]

  def get_messages(self) -> list[Message]:
    result: list[Message] = []
    if self._system:
      result.append(self._system)
    result.extend(self._messages)
    return result

  def clear(self) -> None:
    self._messages.clear()
    self._system = None
