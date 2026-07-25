"""Tests for ConversationMemory."""

from devai.core.models import Message
from devai.memory.conversation import ConversationMemory


def test_add_and_retrieve():
    mem = ConversationMemory()
    mem.add(Message.user("hi"))
    mem.add(Message.assistant("hello"))
    assert len(mem) == 2
    assert mem.get_messages()[0].content == "hi"


def test_max_messages():
    mem = ConversationMemory(max_messages=2)
    mem.add(Message.user("1"))
    mem.add(Message.user("2"))
    mem.add(Message.user("3"))
    assert len(mem) == 2
    assert mem.get_messages()[0].content == "2"


def test_clear():
    mem = ConversationMemory()
    mem.add(Message.user("hi"))
    mem.clear()
    assert len(mem) == 0


def test_last_messages():
    mem = ConversationMemory()
    mem.add(Message.user("first"))
    mem.add(Message.assistant("reply"))
    mem.add(Message.user("second"))
    assert mem.last_user_message().content == "second"
    assert mem.last_assistant_message().content == "reply"


def test_to_text():
    mem = ConversationMemory()
    mem.add(Message.user("hello"))
    text = mem.to_text()
    assert "USER: hello" in text
