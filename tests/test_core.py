"""Tests for core models and config."""

import pytest

from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, Tool, ToolCall


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hello")
    d = msg.to_dict()
    assert d["role"] == "user"
    assert d["content"] == "hello"


def test_tool_openai_schema():
    tool = Tool(
        name="search",
        description="Search files",
        parameters={"type": "object", "properties": {"q": {"type": "string"}}},
    )
    schema = tool.to_openai_schema()
    assert schema["function"]["name"] == "search"


def test_tool_call():
    tc = ToolCall(id="1", name="read_file", arguments={"path": "main.py"})
    assert tc.name == "read_file"


def test_config_defaults():
    config = DevAIConfig()
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.7


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("DEVAI_API_KEY", "test-key")
    monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
    config = DevAIConfig.from_env()
    assert config.api_key == "test-key"
    assert config.model == "gpt-4"
