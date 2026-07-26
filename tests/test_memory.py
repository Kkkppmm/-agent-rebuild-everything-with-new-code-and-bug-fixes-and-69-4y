"""Tests for conversation memory."""

from devai.core.models import Role
from devai.memory import ConversationMemory


class TestConversationMemory:
    def test_add_messages(self):
        mem = ConversationMemory()
        mem.add_user("Hello")
        mem.add_assistant("Hi there")
        assert len(mem) == 2

    def test_get_messages(self):
        mem = ConversationMemory()
        mem.add_system("You are helpful")
        mem.add_user("Question")
        msgs = mem.get_messages(include_system=False)
        assert len(msgs) == 1
        assert msgs[0].role == Role.USER

    def test_trim(self):
        mem = ConversationMemory(max_messages=3)
        for i in range(10):
            mem.add_user(f"msg {i}")
        assert len(mem) <= 3

    def test_clear(self):
        mem = ConversationMemory()
        mem.add_user("test")
        mem.clear()
        assert len(mem) == 0
