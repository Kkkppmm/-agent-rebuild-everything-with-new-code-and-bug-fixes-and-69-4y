"""Tests for LLMClient with mocked HTTP."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, ToolDefinition


def _mock_response(content: str = "Hello!", tool_calls: list | None = None):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"message": message, "finish_reason": "stop"}],
    }


def test_chat_sync():
    config = DevAIConfig(api_key="test", base_url="https://api.example.com/v1")
    client = LLMClient(config)

    mock_resp = MagicMock()
    mock_resp.json.return_value = _mock_response("Hi there")
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        result = client.chat([Message.user("hello")])
        assert result.content == "Hi there"
        mock_client.post.assert_called_once()


@pytest.mark.asyncio
async def test_chat_async():
    config = DevAIConfig(api_key="test")
    client = LLMClient(config)

    mock_resp = MagicMock()
    mock_resp.json.return_value = _mock_response("Async reply")
    mock_resp.raise_for_status = MagicMock()

    mock_http = AsyncMock()
    mock_http.post = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await client.achat([Message.user("hello")])
        assert result.content == "Async reply"


def test_build_payload_with_tools():
    config = DevAIConfig(api_key="test")
    client = LLMClient(config)
    tools = [ToolDefinition(name="fn", description="A function")]
    payload = client._build_payload([Message.user("hi")], tools=tools)
    assert "tools" in payload
    assert payload["tools"][0]["function"]["name"] == "fn"


def test_stream():
    config = DevAIConfig(api_key="test")
    client = LLMClient(config)

    lines = [
        'data: {"choices":[{"delta":{"content":"Hel"}}]}',
        'data: {"choices":[{"delta":{"content":"lo"}}]}',
        "data: [DONE]",
    ]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.iter_lines = MagicMock(return_value=iter(lines))

    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__enter__ = MagicMock(return_value=mock_response)
    mock_stream_ctx.__exit__ = MagicMock(return_value=False)

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.stream.return_value = mock_stream_ctx
        mock_client_cls.return_value = mock_client

        chunks = list(client.stream([Message.user("hi")]))
        assert chunks == ["Hel", "lo"]
