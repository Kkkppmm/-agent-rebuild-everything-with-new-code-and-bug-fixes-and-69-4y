"""Tests for streaming support."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, StreamChunk
from devai.core.client import LLMClient
from devai.chains.chain import Chain


def _make_sse_lines(chunks: list[str]) -> list[str]:
    lines = []
    for text in chunks:
        data = json.dumps({"choices": [{"delta": {"content": text}, "finish_reason": None}]})
        lines.append(f"data: {data}")
    lines.append("data: [DONE]")
    return lines


class TestStreaming:
    @pytest.fixture
    def config(self):
        return DevAIConfig(api_key="test-key")

    @pytest.mark.asyncio
    async def test_stream_yields_chunks(self, config):
        client = LLMClient(config)
        lines = _make_sse_lines(["Hello", " world"])

        async def mock_aiter_lines():
            for line in lines:
                yield line

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.aiter_lines = mock_aiter_lines
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        client._client.stream = MagicMock(return_value=mock_response)

        messages = [Message(role=Role.USER, content="Hi")]
        chunks = []
        async for chunk in client.stream(messages):
            chunks.append(chunk)

        assert len(chunks) == 2
        assert chunks[0].content == "Hello"
        assert chunks[1].content == " world"
        await client.close()

    @pytest.mark.asyncio
    async def test_chain_stream(self, config):
        chain = Chain("Say {word}", config=config)
        lines = _make_sse_lines(["test"])

        async def mock_aiter_lines():
            for line in lines:
                yield line

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.aiter_lines = mock_aiter_lines
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        chain.client._client.stream = MagicMock(return_value=mock_response)

        parts = []
        async for part in chain.stream(word="hello"):
            parts.append(part)

        assert parts == ["test"]
        await chain.close()

    def test_stream_sync(self, config):
        client = LLMClient(config)
        lines = _make_sse_lines(["a", "b"])

        async def mock_aiter_lines():
            for line in lines:
                yield line

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.aiter_lines = mock_aiter_lines
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        client._client.stream = MagicMock(return_value=mock_response)

        chunks = client.stream_sync([Message(role=Role.USER, content="hi")])
        assert [c.content for c in chunks] == ["a", "b"]
