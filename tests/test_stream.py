"""Tests for streaming utilities."""

import pytest

from devai import MockLLMClient, StreamCollector, StreamResult
from devai.core.models import Message


class TestStreamResult:
    def test_tokens_approx(self):
        result = StreamResult(text="one two three four", chunk_count=4)
        assert result.tokens_approx >= 4


class TestStreamCollector:
    def test_collect_sync(self):
        client = MockLLMClient(default_response="hello world stream")
        messages = [Message.user("test")]
        stream = client.stream(messages)
        chunks: list[str] = []
        result = StreamCollector.collect(stream, on_chunk=chunks.append, store_chunks=True)
        assert "hello" in result.text
        assert result.chunk_count > 0
        assert len(chunks) == result.chunk_count
        assert result.elapsed_ms >= 0

    @pytest.mark.asyncio
    async def test_collect_async(self):
        client = MockLLMClient(default_response="async stream test")
        messages = [Message.user("test")]
        result = await StreamCollector.afrom_messages(client, messages)
        assert "async" in result.text
        assert result.chunk_count > 0

    def test_from_messages(self):
        client = MockLLMClient(default_response="from messages")
        messages = [Message.user("explain")]
        result = StreamCollector.from_messages(client, messages)
        assert "from" in result.text

    def test_print_stream(self):
        client = MockLLMClient(default_response="print me")
        stream = client.stream([Message.user("x")])
        result = StreamCollector.print_stream(stream)
        assert "print" in result.text
