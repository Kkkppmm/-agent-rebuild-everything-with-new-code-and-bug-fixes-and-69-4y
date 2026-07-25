"""Tests for DevAI core module."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError, AuthenticationError, ConfigurationError, RateLimitError
from devai.core.models import Message, Role, Tool, ToolCall, CompletionResponse
from devai.core.client import LLMClient


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig(api_key="test-key")
        assert config.model == "gpt-4o-mini"
        assert config.temperature == 0.7
        assert config.max_retries == 3

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("DEVAI_API_KEY", "env-key")
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
        config = DevAIConfig.from_env()
        assert config.api_key == "env-key"
        assert config.model == "gpt-4"

    def test_with_overrides(self):
        config = DevAIConfig(api_key="k").with_overrides(model="gpt-4", temperature=0.5)
        assert config.model == "gpt-4"
        assert config.temperature == 0.5
        assert config.api_key == "k"

    def test_missing_api_key_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigurationError):
                LLMClient(DevAIConfig(api_key=None))


class TestModels:
    def test_message_to_dict(self):
        msg = Message(role=Role.USER, content="hello")
        d = msg.to_dict()
        assert d == {"role": "user", "content": "hello"}

    def test_tool_call_to_dict(self):
        tc = ToolCall(id="1", name="search", arguments={"q": "test"})
        d = tc.to_dict()
        assert d["function"]["name"] == "search"
        assert json.loads(d["function"]["arguments"]) == {"q": "test"}

    def test_tool_to_dict(self):
        tool = Tool(name="read", description="Read a file", parameters={"type": "object"})
        d = tool.to_dict()
        assert d["type"] == "function"
        assert d["function"]["name"] == "read"


class TestLLMClient:
    @pytest.fixture
    def config(self):
        return DevAIConfig(api_key="test-key", max_retries=2, retry_delay=0.01)

    @pytest.fixture
    def mock_response_data(self):
        return {
            "choices": [{
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }

    @pytest.mark.asyncio
    async def test_chat_success(self, config, mock_response_data):
        client = LLMClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data
        client._client.post = AsyncMock(return_value=mock_resp)

        messages = [Message(role=Role.USER, content="Hi")]
        result = await client.chat(messages)
        assert result.content == "Hello!"
        assert result.finish_reason == "stop"
        await client.close()

    @pytest.mark.asyncio
    async def test_chat_with_tools(self, config):
        client = LLMClient(config)
        data = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "search", "arguments": '{"q": "test"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = data
        client._client.post = AsyncMock(return_value=mock_resp)

        tools = [Tool(name="search", description="Search")]
        result = await client.chat([Message(role=Role.USER, content="search")], tools=tools)
        assert result.tool_calls is not None
        assert result.tool_calls[0].name == "search"
        await client.close()

    @pytest.mark.asyncio
    async def test_rate_limit_error(self, config):
        client = LLMClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "rate limited"
        client._client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(APIError):
            await client.chat([Message(role=Role.USER, content="hi")])
        await client.close()

    @pytest.mark.asyncio
    async def test_auth_error(self, config):
        client = LLMClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "unauthorized"
        client._client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(AuthenticationError):
            await client.chat([Message(role=Role.USER, content="hi")])
        await client.close()

    def test_chat_sync(self, config, mock_response_data):
        client = LLMClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data
        client._client.post = AsyncMock(return_value=mock_resp)

        result = client.chat_sync([Message(role=Role.USER, content="Hi")])
        assert result.content == "Hello!"
