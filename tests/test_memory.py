"""Tests for DevAI memory."""

from devai.core.models import Role, ToolCall
from devai.memory.conversation import ConversationMemory


class TestConversationMemory:
    def test_add_and_get(self):
        mem = ConversationMemory()
        mem.add(Role.USER, "Hello")
        mem.add(Role.ASSISTANT, "Hi there!")
        messages = mem.get_messages()
        assert len(messages) == 2
        assert messages[0].content == "Hello"

    def test_add_tool_result(self):
        mem = ConversationMemory()
        mem.add_tool_result("call_1", "result data")
        messages = mem.get_messages()
        assert messages[0].role == Role.TOOL
        assert messages[0].tool_call_id == "call_1"

    def test_clear(self):
        mem = ConversationMemory()
        mem.add(Role.USER, "test")
        mem.clear()
        assert len(mem) == 0

    def test_token_count(self):
        mem = ConversationMemory()
        mem.add(Role.USER, "a" * 100)
        assert mem.token_count > 0

    def test_truncation(self):
        mem = ConversationMemory(max_tokens=10)
        mem.add(Role.USER, "a" * 200)
        mem.add(Role.ASSISTANT, "short")
        assert mem.token_count <= 10 + 10  # some buffer for estimation

    def test_summary(self):
        mem = ConversationMemory()
        mem.add(Role.USER, "What is Python?")
        summary = mem.summary()
        assert "USER" in summary
        assert "Python" in summary

    def test_to_dict_list(self):
        mem = ConversationMemory()
        mem.add(Role.USER, "test")
        d = mem.to_dict_list()
        assert d[0]["role"] == "user"
