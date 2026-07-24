"""Tests for conversation memory."""

from devai.core.models import Role
from devai.memory import ConversationMemory


def test_memory_add_and_retrieve():
    mem = ConversationMemory()
    mem.add_user("Hello")
    mem.add_assistant("Hi there!")
    msgs = mem.messages()
    assert len(msgs) == 2
    assert msgs[0].role == Role.USER
    assert msgs[1].content == "Hi there!"


def test_memory_clear():
    mem = ConversationMemory()
    mem.add_user("test")
    mem.clear()
    assert len(mem) == 0


def test_memory_trim():
    mem = ConversationMemory(max_messages=3)
    for i in range(5):
        mem.add_user(f"msg {i}")
    assert len(mem) <= 3
