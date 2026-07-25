"""Tests for conversation memory."""

from devai.core.models import Role
from devai.memory.conversation import ConversationMemory


def test_memory_system_and_messages():
    memory = ConversationMemory(system="Be helpful.", max_messages=5)
    memory.add(Role.USER, "Hi")
    memory.add(Role.ASSISTANT, "Hello!")
    messages = memory.messages()
    assert len(messages) == 3
    assert messages[0].role == Role.SYSTEM
    assert messages[-1].content == "Hello!"


def test_memory_rolling_window():
    memory = ConversationMemory(max_messages=2)
    memory.add(Role.USER, "1")
    memory.add(Role.ASSISTANT, "2")
    memory.add(Role.USER, "3")
    assert len(memory) == 2
    assert memory.messages()[0].content == "2"


def test_memory_clear():
    memory = ConversationMemory(system="sys")
    memory.add(Role.USER, "test")
    memory.clear()
    assert len(memory) == 0
    assert len(memory.messages()) == 1  # system only
