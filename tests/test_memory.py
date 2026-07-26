"""Tests for conversation memory."""

from devai.memory.conversation import ConversationMemory
from devai.core.models import Message, Role


def test_add_messages():
    mem = ConversationMemory()
    mem.add_user("hello")
    mem.add_assistant("hi there")
    assert len(mem) == 2


def test_get_messages():
    mem = ConversationMemory()
    mem.add_system("system prompt")
    msgs = mem.get_messages()
    assert msgs[0].role == Role.SYSTEM


def test_clear():
    mem = ConversationMemory()
    mem.add_user("test")
    mem.clear()
    assert len(mem) == 0


def test_truncation():
    mem = ConversationMemory(max_tokens=10)
    for i in range(20):
        mem.add_user(f"message number {i} with some extra text")
    assert len(mem) < 20


def test_summary():
    mem = ConversationMemory()
    mem.add_user("question")
    mem.add_assistant("answer")
    summary = mem.summary()
    assert "question" in summary
    assert "answer" in summary
