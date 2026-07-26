"""Tests for conversation memory."""

from devai.core.models import Message
from devai.memory.conversation import ConversationMemory


def test_add_messages():
    mem = ConversationMemory()
    mem.add_user("Hello")
    mem.add_assistant("Hi there!")
    assert len(mem) == 2


def test_system_message():
    mem = ConversationMemory(system_message="You are helpful.")
    msgs = mem.get_messages()
    assert msgs[0].role == "system"


def test_get_context_truncation():
    mem = ConversationMemory(max_tokens=10)
    mem.add_user("A" * 200)
    mem.add_assistant("B" * 200)
    context = mem.get_context()
    total = sum(len(m.content or "") for m in context)
    assert total < 400


def test_clear_keeps_system():
    mem = ConversationMemory(system_message="System")
    mem.add_user("Hello")
    mem.clear()
    assert len(mem) == 1
    assert mem.get_messages()[0].role == "system"


def test_token_count():
    mem = ConversationMemory()
    mem.add_user("Hello world")
    assert mem.token_count > 0
