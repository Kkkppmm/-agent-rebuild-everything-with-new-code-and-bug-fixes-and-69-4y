"""Tests for DevAI core models and config."""

import pytest

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigurationError
from devai.core.models import Message, Role, ToolCall, ToolDefinition


def test_message_to_dict():
  msg = Message(role=Role.USER, content="hello")
  assert msg.to_dict() == {"role": "user", "content": "hello"}


def test_tool_definition_openai_schema():
  tool = ToolDefinition(
    name="read_file",
    description="Read a file",
    parameters={"type": "object", "properties": {"path": {"type": "string"}}},
  )
  schema = tool.to_openai_schema()
  assert schema["function"]["name"] == "read_file"


def test_config_from_env(monkeypatch):
  monkeypatch.setenv("DEVAI_PROVIDER", "mock")
  monkeypatch.setenv("DEVAI_MODEL", "test-model")
  config = DevAIConfig.from_env()
  assert config.provider == "mock"
  assert config.model == "test-model"


def test_config_validate_provider_missing_key():
  config = DevAIConfig(provider="openai", api_key=None)
  with pytest.raises(ConfigurationError):
    config.validate_provider()


def test_config_validate_mock_no_key():
  config = DevAIConfig(provider="mock")
  config.validate_provider()  # should not raise


def test_tool_call_model():
  tc = ToolCall(id="1", name="search", arguments={"query": "TODO"})
  assert tc.name == "search"
  assert tc.arguments["query"] == "TODO"
