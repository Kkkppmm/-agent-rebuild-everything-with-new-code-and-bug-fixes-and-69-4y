"""Tests for conversation memory."""

from devai.core.models import Role
from devai.memory import ConversationMemory


def test_add_messages():
    mem = ConversationMemory()
    mem.add_user("Hello")
    mem.add_assistant("Hi there!")
    assert len(mem) == 2


def test_get_messages():
    mem = ConversationMemory()
    mem.add_user("Q")
    msgs = mem.get_messages()
    assert msgs[0].role == Role.USER
    assert msgs[0].content == "Q"


def test_windowing():
    mem = ConversationMemory(max_messages=3)
    mem.add_system("You are helpful")
    for i in range(5):
        mem.add_user(f"msg {i}")
    assert len(mem) <= 3


def test_clear():
    mem = ConversationMemory()
    mem.add_user("test")
    mem.clear()
    assert len(mem) == 0
