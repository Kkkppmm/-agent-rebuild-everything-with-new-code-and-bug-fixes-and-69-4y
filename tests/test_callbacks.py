"""Tests for DevAI observability callbacks."""

import pytest

from devai.core import LoggingCallback, MockLLMClient, ObservedLLMClient
from devai.core.models import Message


class TestObservedLLMClient:
    @pytest.fixture
    def mock(self):
        return MockLLMClient(default_response="Hello world")

    @pytest.fixture
    def callback(self):
        return LoggingCallback()

    def test_complete_fires_callbacks(self, mock, callback):
        client = ObservedLLMClient(mock, callbacks=[callback])
        result = client.complete([Message.user("hi")])
        assert result == "Hello world"
        assert len(callback.events) == 2
        assert callback.events[0]["event"] == "start"
        assert callback.events[1]["event"] == "end"

    def test_stream_fires_callbacks(self, mock, callback):
        client = ObservedLLMClient(mock, callbacks=[callback])
        chunks = list(client.stream([Message.user("hi")]))
        assert len(chunks) > 0
        assert callback.events[-1]["event"] == "end"

    @pytest.mark.asyncio
    async def test_acomplete_fires_callbacks(self, mock, callback):
        client = ObservedLLMClient(mock, callbacks=[callback])
        result = await client.acomplete([Message.user("hi")])
        assert result == "Hello world"
        assert callback.events[0]["event"] == "start"
        assert callback.events[1]["event"] == "end"

    @pytest.mark.asyncio
    async def test_astream_fires_callbacks(self, mock, callback):
        client = ObservedLLMClient(mock, callbacks=[callback])
        chunks = []
        async for chunk in client.astream([Message.user("hi")]):
            chunks.append(chunk)
        assert len(chunks) > 0
        assert callback.events[-1]["event"] == "end"

    def test_error_fires_callback(self, callback):
        class FailingClient:
            def complete(self, messages, **kwargs):
                raise RuntimeError("boom")

            def stream(self, messages, **kwargs):
                raise RuntimeError("boom")

            async def acomplete(self, messages, **kwargs):
                raise RuntimeError("boom")

            async def astream(self, messages, **kwargs):
                raise RuntimeError("boom")
                yield  # pragma: no cover

        client = ObservedLLMClient(FailingClient(), callbacks=[callback])
        with pytest.raises(RuntimeError):
            client.complete([Message.user("hi")])
        assert callback.events[-1]["event"] == "error"
