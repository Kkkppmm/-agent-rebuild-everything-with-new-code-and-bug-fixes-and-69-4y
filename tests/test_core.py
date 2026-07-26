"""Tests for DevAI core module."""

import pytest

from devai.core.config import DevAIConfig
from devai.core.client import LLMClient, MockLLMClient, EmbeddingClient
from devai.core.models import Message, ToolCall, ToolDefinition, LLMResponse
from devai.core.exceptions import ConfigurationError, ProviderError
from devai.core.streaming import StreamChunk, collect_stream


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig(api_key="test-key")
        assert config.provider == "openai"
        assert config.model == "gpt-4o-mini"
        assert config.api_key == "test-key"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("DEVAI_API_KEY", "env-key")
        monkeypatch.setenv("DEVAI_PROVIDER", "anthropic")
        monkeypatch.setenv("DEVAI_MODEL", "claude-3")
        config = DevAIConfig()
        assert config.api_key == "env-key"
        assert config.provider == "anthropic"
        assert config.model == "claude-3"

    def test_is_mock(self):
        config = DevAIConfig(provider="mock")
        assert config.is_mock


class TestModels:
    def test_message(self):
        msg = Message(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"

    def test_tool_definition_schema(self):
        tool = ToolDefinition(
            name="search",
            description="Search files",
            parameters={"type": "object", "properties": {"q": {"type": "string"}}},
        )
        schema = tool.to_schema()
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "search"

    def test_llm_response_tool_calls(self):
        response = LLMResponse(content="ok", tool_calls=[])
        assert not response.has_tool_calls
        response2 = LLMResponse(
            content="",
            tool_calls=[ToolCall(id="1", name="test", arguments={})],
        )
        assert response2.has_tool_calls


class TestMockLLMClient:
    def test_complete(self):
        client = MockLLMClient(responses=["Hello", "World"])
        r1 = client.complete("test")
        assert r1.content == "Hello"
        r2 = client.complete("test2")
        assert r2.content == "World"

    def test_stream(self):
        client = MockLLMClient(responses=["Hi"])
        chunks = list(client.stream("test"))
        content = "".join(c.content for c in chunks)
        assert content == "Hi"
        assert chunks[-1].done

    def test_records_calls(self):
        client = MockLLMClient()
        client.complete("prompt", system="sys")
        assert len(client.calls) == 1
        assert client.calls[0]["system"] == "sys"


class TestLLMClient:
    def test_requires_api_key(self):
        with pytest.raises(ConfigurationError):
            LLMClient(DevAIConfig(api_key=None, provider="openai"))

    def test_rejects_mock_provider(self):
        with pytest.raises(ConfigurationError):
            LLMClient(DevAIConfig(provider="mock"))


class TestEmbeddingClient:
    def test_mock_embed(self):
        client = EmbeddingClient(DevAIConfig(provider="mock"))
        embeddings = client.embed(["hello", "world"])
        assert len(embeddings) == 2
        assert len(embeddings[0]) == 8

    def test_embed_one(self):
        client = EmbeddingClient(DevAIConfig(provider="mock"))
        emb = client.embed_one("test")
        assert len(emb) == 8


class TestStreaming:
    def test_collect_stream(self):
        chunks = [StreamChunk("a"), StreamChunk("b"), StreamChunk("", done=True)]
        assert collect_stream(iter(chunks)) == "ab"
