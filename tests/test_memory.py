"""Tests for memory."""

from devai.core.models import Role
from devai.memory import ConversationMemory


def test_add_and_get():
    mem = ConversationMemory()
    mem.add(Role.USER, "hello")
    mem.add(Role.ASSISTANT, "hi")
    messages = mem.get_messages()
    assert len(messages) == 2
    assert messages[0].content == "hello"


def test_clear():
    mem = ConversationMemory()
    mem.add(Role.USER, "test")
    mem.clear()
    assert mem.message_count == 0


def test_max_messages():
    mem = ConversationMemory(max_messages=3)
    for i in range(5):
        mem.add(Role.USER, f"msg {i}")
    assert mem.message_count == 3
    assert mem.get_messages()[0].content == "msg 2"
