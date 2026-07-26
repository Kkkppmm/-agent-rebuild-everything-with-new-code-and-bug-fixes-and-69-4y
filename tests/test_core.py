"""Tests for core module."""

import json

import pytest

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigError
from devai.core.messages import Message, Role, ToolCall, ToolDefinition
from devai.core.client import MockLLMClient


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig(api_key="test-key")
        assert config.model == "gpt-4o-mini"
        assert config.temperature == 0.7

    def test_require_api_key_raises(self):
        config = DevAIConfig(api_key=None)
        with pytest.raises(ConfigError):
            config.require_api_key()

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        config = DevAIConfig.from_env()
        assert config.api_key == "env-key"


class TestMessage:
    def test_system_message(self):
        msg = Message.system("hello")
        assert msg.role == Role.SYSTEM
        assert msg.content == "hello"

    def test_user_message(self):
        msg = Message.user("question")
        assert msg.role == Role.USER

    def test_assistant_with_tools(self):
        tc = ToolCall(id="1", name="search", arguments={"q": "test"})
        msg = Message.assistant("", tool_calls=[tc])
        d = msg.to_dict()
        assert "tool_calls" in d
        assert d["tool_calls"][0]["function"]["name"] == "search"

    def test_tool_message(self):
        msg = Message.tool("result", tool_call_id="1", name="search")
        assert msg.role == Role.TOOL
        assert msg.tool_call_id == "1"


class TestToolDefinition:
    def test_openai_schema(self):
        td = ToolDefinition(
            name="search",
            description="Search code",
            parameters={"type": "object", "properties": {}},
        )
        schema = td.to_openai_schema()
        assert schema["function"]["name"] == "search"


class TestMockLLMClient:
    def test_complete(self):
        client = MockLLMClient(responses=["Hello", "World"])
        r1 = client.complete([Message.user("hi")])
        r2 = client.complete([Message.user("hi")])
        assert r1.content == "Hello"
        assert r2.content == "World"

    def test_json_mode(self):
        client = MockLLMClient(responses=["plain text"])
        result = client.complete([Message.user("hi")], json_mode=True)
        data = json.loads(result.content)
        assert "result" in data

    def test_stream(self):
        client = MockLLMClient(responses=["one two three"])
        tokens = list(client.stream([Message.user("hi")]))
        assert len(tokens) == 3

    @pytest.mark.asyncio
    async def test_acomplete(self):
        client = MockLLMClient()
        result = await client.acomplete([Message.user("hi")])
        assert result.content

    @pytest.mark.asyncio
    async def test_astream(self):
        client = MockLLMClient(responses=["a b"])
        tokens = [t async for t in client.astream([Message.user("hi")])]
        assert len(tokens) == 2
