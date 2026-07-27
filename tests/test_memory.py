"""Tests for DevAI memory."""

from devai.memory import ConversationMemory
from devai.core.models import Message


class TestConversationMemory:
    def test_add_messages(self):
        mem = ConversationMemory()
        mem.add_user("Hello")
        mem.add_assistant("Hi there")
        assert len(mem) == 2

    def test_windowing(self):
        mem = ConversationMemory(max_messages=3)
        for i in range(5):
            mem.add_user(f"msg {i}")
        assert len(mem) == 3
        assert mem.get_messages()[0].content == "msg 2"

    def test_clear(self):
        mem = ConversationMemory()
        mem.add_user("test")
        mem.clear()
        assert len(mem) == 0

    def test_last(self):
        mem = ConversationMemory()
        assert mem.last is None
        mem.add_user("hello")
        assert mem.last.content == "hello"

    def test_to_prompt(self):
        mem = ConversationMemory()
        mem.add_user("What is Python?")
        mem.add_assistant("A programming language.")
        prompt = mem.to_prompt()
        assert "user: What is Python?" in prompt
        assert "assistant: A programming language." in prompt
