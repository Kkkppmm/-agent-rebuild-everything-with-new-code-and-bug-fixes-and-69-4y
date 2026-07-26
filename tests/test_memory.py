"""Tests for DevAI memory."""

from devai.core.models import Message, Role
from devai.memory import ConversationMemory


def test_memory_add():
    mem = ConversationMemory(system_prompt="You are helpful.")
    mem.add_user("Hello")
    mem.add_assistant("Hi there!")
    messages = mem.get_messages()
    assert len(messages) == 3
    assert messages[1].role == Role.USER


def test_memory_windowing():
    mem = ConversationMemory(max_messages=2, system_prompt="System")
    mem.add_user("1")
    mem.add_assistant("2")
    mem.add_user("3")
    messages = mem.get_messages()
    assert messages[0].role == Role.SYSTEM
    assert len(messages) == 3  # system + 2 recent


def test_memory_clear():
    mem = ConversationMemory(system_prompt="System")
    mem.add_user("test")
    mem.clear()
    assert len(mem) == 1
