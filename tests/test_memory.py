"""Tests for DevAI memory."""

from devai.memory import ConversationMemory


class TestConversationMemory:
    def test_add_messages(self):
        mem = ConversationMemory()
        mem.add_user("Hello")
        mem.add_assistant("Hi there")
        assert len(mem) == 2

    def test_system_message(self):
        mem = ConversationMemory(system_message="Be helpful")
        msgs = mem.get_messages()
        assert msgs[0].role == "system"

    def test_clear_keeps_system(self):
        mem = ConversationMemory(system_message="System")
        mem.add_user("Hello")
        mem.clear()
        assert len(mem) == 1
        assert mem.get_messages()[0].role == "system"

    def test_token_count(self):
        mem = ConversationMemory()
        mem.add_user("Hello world")
        assert mem.token_count > 0

    def test_trim_on_overflow(self):
        mem = ConversationMemory(max_tokens=10)
        for i in range(20):
            mem.add_user(f"Message number {i} with some extra text to use tokens")
        assert mem.token_count <= 10 + 20  # some tolerance
