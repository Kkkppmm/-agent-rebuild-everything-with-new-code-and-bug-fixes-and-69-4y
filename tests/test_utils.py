"""Tests for memory and utilities."""

from devai.core.models import Role
from devai.memory import ConversationMemory
from devai.utils import estimate_tokens, extract_code_blocks, truncate_to_tokens


def test_conversation_memory():
  mem = ConversationMemory(max_messages=4, system_prompt="You are helpful.")
  mem.add_user("Hello")
  mem.add_assistant("Hi there!")
  mem.add_user("How are you?")
  messages = mem.get_messages()
  assert len(messages) == 4  # system + 3
  assert messages[0].role == Role.SYSTEM


def test_conversation_memory_trim():
  mem = ConversationMemory(max_messages=2)
  for i in range(5):
    mem.add_user(f"msg {i}")
  assert len(mem) <= 3  # max 2 non-system + possible system


def test_estimate_tokens():
  assert estimate_tokens("hello world") >= 1


def test_extract_code_blocks():
  text = "Here:\n```python\nx = 1\n```\nDone."
  blocks = extract_code_blocks(text)
  assert len(blocks) == 1
  assert "x = 1" in blocks[0]


def test_truncate_to_tokens():
  long_text = "a" * 1000
  truncated = truncate_to_tokens(long_text, max_tokens=10)
  assert len(truncated) < len(long_text)
  assert truncated.endswith("...")
