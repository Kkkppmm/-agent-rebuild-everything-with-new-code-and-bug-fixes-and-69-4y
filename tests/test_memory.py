"""Tests for DevAI memory."""

import json
from pathlib import Path

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

    def test_save_and_load(self, tmp_path: Path):
        mem = ConversationMemory(system_message="System", max_tokens=4000)
        mem.add_user("Hello")
        mem.add_assistant("Hi there")

        path = tmp_path / "memory.json"
        mem.save(path)

        loaded = ConversationMemory.load(path)
        assert loaded.max_tokens == 4000
        assert len(loaded) == 3
        assert loaded.get_messages()[1].content == "Hello"
        assert loaded.get_messages()[2].content == "Hi there"

    def test_to_dict_roundtrip(self):
        mem = ConversationMemory()
        mem.add_user("Test")
        data = mem.to_dict()
        restored = ConversationMemory.from_dict(data)
        assert len(restored) == 1
        assert restored.get_messages()[0].content == "Test"
        assert json.loads(json.dumps(data)) == data
