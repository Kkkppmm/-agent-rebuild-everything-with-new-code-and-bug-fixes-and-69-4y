"""Tests for LLM clients."""

import json

import pytest

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import ToolCall


def test_mock_client_basic():
    client = MockLLMClient(responses=["Hello!", "World!"])
    r1 = client.chat([{"role": "user", "content": "Hi"}])
    assert r1.content == "Hello!"
    r2 = client.chat([{"role": "user", "content": "Again"}])
    assert r2.content == "World!"


def test_mock_client_json_mode():
    client = MockLLMClient(responses=['{"key": "value"}'])
    result = client.chat_json([{"role": "user", "content": "test"}])
    assert result == {"key": "value"}


def test_mock_client_json_mode_wraps_plain_text():
    client = MockLLMClient(responses=["plain text"])
    result = client.chat_json([{"role": "user", "content": "test"}])
    assert "result" in result


def test_mock_client_stream():
    client = MockLLMClient(responses=["hello world"])
    tokens = list(client.stream([{"role": "user", "content": "test"}]))
    assert len(tokens) == 2


def test_mock_client_tool_calls():
    tc = ToolCall(id="1", name="read_file", arguments='{"path": "a.py"}')
    client = MockLLMClient(
        responses=["done"],
        tool_responses=[[tc]],
    )
    r = client.chat([{"role": "user", "content": "read a.py"}])
    assert r.has_tool_calls
    assert r.tool_calls[0].name == "read_file"


def test_mock_client_call_history():
    client = MockLLMClient()
    client.chat([{"role": "user", "content": "test"}])
    assert len(client.call_history) == 1


def test_mock_client_reset():
    client = MockLLMClient()
    client.chat([{"role": "user", "content": "test"}])
    client.reset()
    assert len(client.call_history) == 0


def test_llm_client_build_payload():
    config = DevAIConfig(api_key="test")
    client = LLMClient(config)
    payload = client._build_payload([{"role": "user", "content": "hi"}], json_mode=True)
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["messages"][0]["content"] == "hi"
