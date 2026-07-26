"""Tests for memory module."""

from devai.core.models import Role
from devai.memory import ConversationMemory


class TestConversationMemory:
    def test_add_and_len(self):
        mem = ConversationMemory()
        mem.add_user("hello")
        mem.add_assistant("hi")
        assert len(mem) == 2

    def test_windowing(self):
        mem = ConversationMemory(max_messages=3)
        for i in range(5):
            mem.add_user(f"msg {i}")
        assert len(mem) == 3
        assert mem.messages[-1].content == "msg 4"

    def test_clear(self):
        mem = ConversationMemory()
        mem.add_user("hi")
        mem.clear()
        assert len(mem) == 0

    def test_get_context_exclude_system(self):
        mem = ConversationMemory()
        mem.add_system("sys")
        mem.add_user("user")
        ctx = mem.get_context(include_system=False)
        assert all(m.role != Role.SYSTEM for m in ctx)
