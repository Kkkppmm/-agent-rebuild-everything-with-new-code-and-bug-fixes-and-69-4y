"""Tests for MockLLMClient and EmbeddingClient."""

import pytest

from devai.core.config import DevAIConfig
from devai.core.embeddings import EmbeddingClient, MockEmbeddingClient, cosine_similarity
from devai.core.exceptions import ConfigurationError
from devai.core.mock import MockLLMClient
from devai.core.models import CompletionResponse, Message, Role, ToolCall


class TestMockLLMClient:
    @pytest.mark.asyncio
    async def test_queued_responses(self):
        client = MockLLMClient(responses=["first", "second"])
        r1 = await client.chat([Message(role=Role.USER, content="hi")])
        r2 = await client.chat([Message(role=Role.USER, content="again")])
        assert r1.content == "first"
        assert r2.content == "second"

    @pytest.mark.asyncio
    async def test_default_response(self):
        client = MockLLMClient(default="fallback")
        result = await client.chat([Message(role=Role.USER, content="hi")])
        assert result.content == "fallback"

    @pytest.mark.asyncio
    async def test_records_calls(self):
        client = MockLLMClient()
        await client.chat([Message(role=Role.USER, content="test")], temperature=0.2)
        assert len(client.calls) == 1
        assert client.calls[0]["temperature"] == 0.2

    @pytest.mark.asyncio
    async def test_stream_splits_words(self):
        client = MockLLMClient(responses=["hello world"])
        chunks = []
        async for chunk in client.stream([Message(role=Role.USER, content="hi")]):
            chunks.append(chunk.content)
        assert "".join(chunks).strip() == "hello world"

    @pytest.mark.asyncio
    async def test_tool_loop_factory(self):
        client = MockLLMClient.with_tool_loop("search", {"q": "devai"})
        first = await client.chat([Message(role=Role.USER, content="go")])
        second = await client.chat([Message(role=Role.USER, content="go")])
        assert first.tool_calls is not None
        assert first.tool_calls[0].name == "search"
        assert second.content == "Task complete."


class TestMockEmbeddingClient:
    @pytest.mark.asyncio
    async def test_embed_returns_normalized_vectors(self):
        client = MockEmbeddingClient(dimensions=8)
        vectors = await client.embed(["hello", "world"])
        assert len(vectors) == 2
        assert len(vectors[0]) == 8
        assert vectors[0] != vectors[1]

    def test_embed_sync(self):
        client = MockEmbeddingClient()
        vectors = client.embed_sync(["a", "b"])
        assert len(vectors) == 2

    def test_cosine_similarity_identical(self):
        client = MockEmbeddingClient()
        vector = client.embed_sync(["same"])[0]
        assert cosine_similarity(vector, vector) == pytest.approx(1.0)


class TestEmbeddingClient:
    def test_missing_api_key_raises(self):
        with pytest.raises(ConfigurationError):
            EmbeddingClient(DevAIConfig(api_key=None))
