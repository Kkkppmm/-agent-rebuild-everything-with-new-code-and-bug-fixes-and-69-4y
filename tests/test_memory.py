"""Tests for conversation memory."""

from devai.core.models import Message, Role
from devai.memory.conversation import ConversationMemory


def test_add_messages():
  mem = ConversationMemory()
  mem.add_user("Hello")
  mem.add_assistant("Hi there!")
  assert len(mem) == 2
  assert mem.messages[0].role == Role.USER


def test_max_messages_trim():
  mem = ConversationMemory(max_messages=3)
  for i in range(5):
    mem.add_user(f"msg {i}")
  assert len(mem) <= 3


def test_clear():
  mem = ConversationMemory()
  mem.add_user("test")
  mem.clear()
  assert len(mem) == 0


def test_system_messages_preserved():
  mem = ConversationMemory(max_messages=3)
  mem.add_system("Be helpful")
  for i in range(5):
    mem.add_user(f"msg {i}")
  roles = [m.role for m in mem.messages]
  assert Role.SYSTEM in roles
