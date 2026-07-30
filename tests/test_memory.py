"""Tests for DevAI memory."""

from devai.memory import ConversationMemory, ConversationStore


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

    def test_save_and_load(self, tmp_path):
        mem = ConversationMemory(system_message="System")
        mem.add_user("Hello")
        mem.add_assistant("Hi")
        path = tmp_path / "conv.json"
        mem.save(path)
        restored = ConversationMemory.load(path)
        assert len(restored) == 3
        assert restored.get_messages()[1].content == "Hello"

    def test_to_dict_from_dict(self):
        mem = ConversationMemory()
        mem.add_user("test")
        data = mem.to_dict()
        restored = ConversationMemory.from_dict(data)
        assert len(restored) == 1


class TestConversationStore:
    def test_get_save_list_delete(self, tmp_path):
        store = ConversationStore(tmp_path)
        mem = store.get("session1")
        mem.add_user("Hello")
        store.save("session1", mem)
        assert "session1" in store.list_names()
        loaded = store.get("session1")
        assert len(loaded) == 1
        assert store.delete("session1")
        assert "session1" not in store.list_names()
