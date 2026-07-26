"""Tests for conversation memory."""

from devai.core.models import Role
from devai.memory.conversation import ConversationMemory


class TestConversationMemory:
    def test_add_messages(self):
        mem = ConversationMemory()
        mem.add_user("Hello")
        mem.add_assistant("Hi there")
        assert len(mem) == 2

    def test_system_prompt(self):
        mem = ConversationMemory(system_prompt="You are helpful.")
        msgs = mem.get_messages()
        assert msgs[0].role == Role.SYSTEM

    def test_clear_keep_system(self):
        mem = ConversationMemory(system_prompt="System")
        mem.add_user("Hello")
        mem.clear(keep_system=True)
        assert len(mem) == 1
        assert mem.get_messages()[0].role == Role.SYSTEM

    def test_trim(self):
        mem = ConversationMemory(max_messages=3)
        for i in range(10):
            mem.add_user(f"msg {i}")
        assert len(mem) == 3
