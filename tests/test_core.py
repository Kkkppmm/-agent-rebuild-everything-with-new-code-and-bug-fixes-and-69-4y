"""Tests for DevAI core module."""

import json

import pytest

from devai import DevAIConfig, MockLLMClient
from devai.core.exceptions import ConfigError, ParseError, ToolError
from devai.core.models import Message, Role, Tool, ToolCall


class TestDevAIConfig:
    def test_defaults(self):
        config = DevAIConfig(api_key="test-key")
        assert config.model == "gpt-4o-mini"
        assert config.max_retries == 3

    def test_validate_missing_key(self):
        config = DevAIConfig()
        with pytest.raises(ConfigError):
            config.validate()

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
        assert d == {"role": "user", "content": "hello"}

    def test_roundtrip(self):
        msg = Message(role=Role.ASSISTANT, content="hi", tool_calls=[
            ToolCall(id="1", name="test", arguments="{}"),
        ])
        d = msg.to_dict()
        restored = Message.from_dict(d)
        assert restored.content == "hi"
        assert len(restored.tool_calls) == 1


class TestMockLLMClient:
    def test_basic_response(self):
        client = MockLLMClient(responses=["Hello!", "World!"])
        r1 = client.chat([{"role": "user", "content": "hi"}])
        assert r1.content == "Hello!"
        r2 = client.chat([{"role": "user", "content": "again"}])
        assert r2.content == "World!"

    def test_json_mode(self):
        client = MockLLMClient(responses=["result text"])
        r = client.chat([{"role": "user", "content": "hi"}], json_mode=True)
        data = json.loads(r.content)
        assert "result" in data

    def test_stream(self):
        client = MockLLMClient(responses=["one two three"])
        chunks = list(client.stream([{"role": "user", "content": "hi"}]))
        text = "".join(c.content for c in chunks)
        assert "one" in text

    def test_records_messages(self):
        client = MockLLMClient()
        client.chat([{"role": "user", "content": "test"}])
        assert len(client.last_messages) == 1
