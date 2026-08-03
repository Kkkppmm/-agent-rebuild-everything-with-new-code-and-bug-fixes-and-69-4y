"""Tests for DevAI core module."""

import pytest

from devai.core import (
    CachedLLMClient,
    DevAIConfig,
    Message,
    MockLLMClient,
    Role,
    Tool,
)
from devai.core.batch import BatchRunner
from devai.core.exceptions import ConfigError


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig(api_key="test-key")
        assert config.model == "gpt-4o-mini"
        assert config.max_tokens == 4096
        assert config.temperature == 0.2

    def test_validate_missing_key(self, monkeypatch):
        monkeypatch.delenv("DEVAI_API_KEY", raising=False)
        config = DevAIConfig()
        with pytest.raises(ConfigError):
            config.validate()

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
        monkeypatch.setenv("DEVAI_API_KEY", "env-key")
        config = DevAIConfig()
        assert config.model == "gpt-4"
        assert config.api_key == "env-key"

    def test_from_env_openai(self, monkeypatch):
        monkeypatch.setenv("DEVAI_PROVIDER", "openai")
        monkeypatch.setenv("DEVAI_API_KEY", "env-key")
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4o")
        config = DevAIConfig.from_env()
        assert config.api_key == "env-key"
        assert config.model == "gpt-4o"

    def test_from_env_mock(self, monkeypatch):
        monkeypatch.setenv("DEVAI_PROVIDER", "mock")
        config = DevAIConfig.from_env()
        assert config.api_key == "mock"
        assert config.model == "mock-model"

    def test_from_env_ollama(self, monkeypatch):
        monkeypatch.setenv("DEVAI_PROVIDER", "ollama")
        monkeypatch.setenv("DEVAI_MODEL", "codellama")
        config = DevAIConfig.from_env()
        assert config.api_key == "ollama"
        assert config.model == "codellama"


class TestMessage:
    def test_system_message(self):
        msg = Message.system("Hello")
        assert msg.role == Role.SYSTEM
        assert msg.content == "Hello"

    def test_user_message(self):
        msg = Message.user("Question")
        assert msg.role == Role.USER

    def test_to_dict(self):
        msg = Message.user("test")
        d = msg.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "test"


class TestTool:
    def test_to_dict(self):
        tool = Tool(name="search", description="Search code", parameters={"type": "object"})
        d = tool.to_dict()
        assert d["type"] == "function"
        assert d["function"]["name"] == "search"


class TestMockLLMClient:
    def test_complete(self):
        client = MockLLMClient(default_response="Hello")
        result = client.complete([Message.user("Hi")])
        assert result == "Hello"
        assert len(client.call_history) == 1

    def test_responses_queue(self):
        client = MockLLMClient(responses=["First", "Second"])
        assert client.complete([Message.user("a")]) == "First"
        assert client.complete([Message.user("b")]) == "Second"
        assert client.complete([Message.user("c")]) == "Mock response from DevAI."

    def test_stream(self):
        client = MockLLMClient(default_response="hello world")
        chunks = list(client.stream([Message.user("Hi")]))
        assert len(chunks) == 2

    @pytest.mark.asyncio
    async def test_acomplete(self):
        client = MockLLMClient(default_response="Async")
        result = await client.acomplete([Message.user("Hi")])
        assert result == "Async"

    @pytest.mark.asyncio
    async def test_astream(self):
        client = MockLLMClient(default_response="one two")
        chunks = []
        async for chunk in client.astream([Message.user("Hi")]):
            chunks.append(chunk)
        assert len(chunks) == 2


class TestCachedLLMClient:
    def test_caching(self):
        inner = MockLLMClient(default_response="Cached")
        cached = CachedLLMClient(inner)
        msgs = [Message.user("test")]
        r1 = cached.complete(msgs)
        r2 = cached.complete(msgs)
        assert r1 == r2 == "Cached"
        assert len(inner.call_history) == 1
        assert cached.cache_size == 1

    def test_clear_cache(self):
        cached = CachedLLMClient(MockLLMClient())
        cached.complete([Message.user("a")])
        assert cached.cache_size == 1
        cached.clear_cache()
        assert cached.cache_size == 0


class TestBatchRunner:
    def test_run_parallel(self):
        client = MockLLMClient(responses=["A", "B", "C"])
        runner = BatchRunner(client, max_workers=2)
        batches = [[Message.user("1")], [Message.user("2")], [Message.user("3")]]
        results = runner.run(batches)
        assert len(results) == 3

    def test_map(self):
        client = MockLLMClient(default_response="result")
        runner = BatchRunner(client)
        results = runner.map(["a", "b"], lambda x: [Message.user(x)])
        assert len(results) == 2
