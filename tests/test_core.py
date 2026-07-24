"""Tests for DevAI core modules."""

import json

import pytest

from devai.core.client import MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import ParseError
from devai.core.models import Message, Role, Tool, ToolCall


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig(api_key="test-key")
        assert config.model == "gpt-4o-mini"
        assert config.temperature == 0.7
        assert config.max_retries == 3

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
        config = DevAIConfig.from_env()
        assert config.api_key == "env-key"
        assert config.model == "gpt-4"


class TestMessage:
    def test_to_dict(self):
        msg = Message(role=Role.USER, content="hello")
        d = msg.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "hello"

    def test_tool_call_message(self):
        tc = ToolCall(id="1", name="search", arguments={"q": "test"})
        msg = Message(role=Role.ASSISTANT, content="", tool_calls=[tc])
        d = msg.to_dict()
        assert "tool_calls" in d
        assert d["tool_calls"][0]["function"]["name"] == "search"


class TestTool:
    def test_to_dict(self):
        tool = Tool(name="read_file", description="Read a file", parameters={"type": "object"})
        d = tool.to_dict()
        assert d["function"]["name"] == "read_file"


class TestMockLLMClient:
    def test_basic_response(self):
        client = MockLLMClient(responses=["Hello", "World"])
        assert client.complete("Hi") == "Hello"
        assert client.complete("Again") == "World"

    def test_json_mode(self):
        client = MockLLMClient(responses=["result text"])
        msg = client.chat([Message(role=Role.USER, content="test")], json_mode=True)
        data = json.loads(msg.content)
        assert "result" in data

    def test_stream(self):
        client = MockLLMClient(responses=["one two three"])
        chunks = list(client.stream([Message(role=Role.USER, content="test")]))
        assert len(chunks) == 3

    def test_tool_call_response(self):
        client = MockLLMClient(responses=['TOOL:search|{"q": "hello"}'])
        tools = [Tool(name="search", description="Search")]
        msg = client.chat([Message(role=Role.USER, content="search")], tools=tools)
        assert msg.tool_calls is not None
        assert msg.tool_calls[0].name == "search"

    def test_history_tracking(self):
        client = MockLLMClient()
        client.complete("test")
        assert len(client.history) == 1
