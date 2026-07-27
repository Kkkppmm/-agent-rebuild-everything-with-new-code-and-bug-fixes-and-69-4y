"""Tests for DevAI core module."""

import json

import pytest

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, ParseError, ToolExecutionError
from devai.core.models import Message, Role, ToolCall, ToolDefinition


def test_devai_config_defaults():
  config = DevAIConfig(api_key="test-key")
  assert config.model == "gpt-4o-mini"
  assert config.temperature == 0.2
  assert config.api_key == "test-key"


def test_devai_config_from_env(monkeypatch):
  monkeypatch.setenv("OPENAI_API_KEY", "env-key")
  monkeypatch.setenv("DEVAI_MODEL", "gpt-4")
  config = DevAIConfig.from_env()
  assert config.api_key == "env-key"
  assert config.model == "gpt-4"


def test_message_to_dict():
  msg = Message(role=Role.USER, content="hello")
  assert msg.to_dict() == {"role": "user", "content": "hello"}


def test_tool_definition_openai_format():
  tool = ToolDefinition(
    name="read_file",
    description="Read a file",
    parameters={"type": "object", "properties": {"path": {"type": "string"}}},
  )
  result = tool.to_openai_tool()
  assert result["type"] == "function"
  assert result["function"]["name"] == "read_file"


def test_mock_llm_client_complete():
  client = MockLLMClient(default_response="Hello!")
  result = client.complete([Message(role=Role.USER, content="Hi")])
  assert result.content == "Hello!"
  assert len(client.calls) == 1


def test_mock_llm_client_responses_queue():
  client = MockLLMClient(responses=["First", "Second"])
  assert client.complete([]).content == "First"
  assert client.complete([]).content == "Second"


def test_mock_llm_client_json_mode():
  client = MockLLMClient(default_response="plain text")
  result = client.complete([], json_mode=True)
  data = json.loads(result.content)
  assert "result" in data


def test_mock_llm_client_tool_calls():
  tc = ToolCall(id="1", name="read_file", arguments={"path": "x.py"})
  client = MockLLMClient(tool_responses=[[tc]])
  result = client.complete([])
  assert len(result.tool_calls) == 1
  assert result.tool_calls[0].name == "read_file"


def test_mock_llm_client_stream():
  client = MockLLMClient(default_response="hello world")
  chunks = list(client.stream([]))
  assert "".join(chunks).strip() == "hello world"


@pytest.mark.asyncio
async def test_mock_llm_client_async():
  client = MockLLMClient(default_response="async ok")
  result = await client.acomplete([])
  assert result.content == "async ok"


@pytest.mark.asyncio
async def test_mock_llm_client_astream():
  client = MockLLMClient(default_response="stream ok")
  chunks = [c async for c in client.astream([])]
  assert "stream" in "".join(chunks)


def test_llm_client_build_payload():
  client = LLMClient(DevAIConfig(api_key="k", model="test-model"))
  payload = client._build_payload(
    [Message(role=Role.USER, content="hi")],
    json_mode=True,
    temperature=0.5,
  )
  assert payload["model"] == "test-model"
  assert payload["response_format"]["type"] == "json_object"
  assert payload["temperature"] == 0.5


def test_llm_client_parse_completion():
  client = LLMClient()
  data = {
    "choices": [{
      "message": {"content": "done", "tool_calls": [{
        "id": "tc1",
        "function": {"name": "test", "arguments": '{"x": 1}'},
      }]},
      "finish_reason": "tool_calls",
    }],
    "usage": {"total_tokens": 10},
  }
  result = client._parse_completion(data)
  assert result.content == "done"
  assert result.tool_calls[0].arguments == {"x": 1}


def test_exceptions_hierarchy():
  assert issubclass(LLMError, Exception)
  assert issubclass(ParseError, Exception)
  assert issubclass(ToolExecutionError, Exception)
