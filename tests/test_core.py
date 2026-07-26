"""Tests for DevAI core module."""

import json

import pytest

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError
from devai.core.models import Message, Role, Tool, ToolCall


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig()
        assert config.model == "gpt-4o-mini"
        assert config.temperature == 0.7

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("DEVAI_API_KEY", "test-key")
        monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
        config = DevAIConfig.from_env()
        assert config.api_key == "test-key"
        assert config.model == "gpt-4"

    def test_with_overrides(self):
        config = DevAIConfig().with_overrides(temperature=0.5)
        assert config.temperature == 0.5
        assert config.model == "gpt-4o-mini"


class TestModels:
    def test_message_to_api_dict(self):
        msg = Message(role=Role.USER, content="hello")
        assert msg.to_api_dict() == {"role": "user", "content": "hello"}

    def test_tool_call_roundtrip(self):
        tc = ToolCall(id="1", name="test", arguments={"a": 1})
        api = tc.to_api_dict()
        assert api["function"]["name"] == "test"
        assert json.loads(api["function"]["arguments"]) == {"a": 1}

    def test_tool_to_api_dict(self):
        tool = Tool(name="fn", description="desc", parameters={"type": "object"})
        assert tool.to_api_dict()["function"]["name"] == "fn"


class TestMockLLMClient:
    def test_basic_chat(self):
        client = MockLLMClient(responses=["Hello!", "World!"])
        msgs = [Message(role=Role.USER, content="hi")]
        r1 = client.chat(msgs)
        assert r1.content == "Hello!"
        r2 = client.chat(msgs)
        assert r2.content == "World!"

    def test_tool_calls(self):
        tc = MockLLMClient.make_tool_call("read_file", {"path": "x.py"})
        client = MockLLMClient(
            responses=["calling tool"],
            tool_responses=[[tc]],
        )
        r = client.chat([Message(role=Role.USER, content="read")])
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0].name == "read_file"

    def test_stream(self):
        client = MockLLMClient(responses=["one two three"])
        tokens = list(client.stream([Message(role=Role.USER, content="go")]))
        assert len(tokens) == 3

    @pytest.mark.asyncio
    async def test_async_chat(self):
        client = MockLLMClient(responses=["async ok"])
        r = await client.achat([Message(role=Role.USER, content="hi")])
        assert r.content == "async ok"


class TestLLMClient:
    def test_parse_response(self):
        client = LLMClient(DevAIConfig(api_key="test"))
        data = {
            "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 10},
        }
        resp = client._parse_response(data)
        assert resp.content == "hi"

    def test_build_payload_json_mode(self):
        client = LLMClient(DevAIConfig(api_key="test"))
        payload = client._build_payload(
            [Message(role=Role.USER, content="hi")], json_mode=True
        )
        assert payload["response_format"] == {"type": "json_object"}
