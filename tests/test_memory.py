"""Tests for conversation memory."""

from devai.core.models import Role
from devai.memory.conversation import ConversationMemory


def test_memory_add():
    mem = ConversationMemory(system_prompt="You are helpful")
    mem.add(Role.USER, "Hello")
    assert len(mem) == 2  # system + user


def test_memory_clear():
    mem = ConversationMemory(system_prompt="System")
    mem.add(Role.USER, "Hello")
    mem.clear()
    assert len(mem) == 1  # only system remains


def test_memory_token_count():
    mem = ConversationMemory()
    mem.add(Role.USER, "Hello world")
    assert mem.token_count > 0


def test_memory_trim():
    mem = ConversationMemory(max_tokens=10)
    mem.add(Role.USER, "A" * 100)
    mem.add(Role.USER, "B" * 100)
    assert mem.token_count <= 10 + 50  # some tolerance
