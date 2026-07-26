"""Tests for LLM clients."""

import json

import pytest

from devai.core.client import MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError
from devai.core.client import LLMClient
from devai.core.models import Message, Role, ToolCall


def test_mock_client_complete():
    client = MockLLMClient(responses=["Hello!", "World!"])
    msg = client.complete([Message(role=Role.USER, content="hi")])
    assert msg.content == "Hello!"
    assert msg.role == Role.ASSISTANT


def test_mock_client_multiple_calls():
    client = MockLLMClient(responses=["a", "b", "c"])
    client.complete([Message(role=Role.USER, content="1")])
    msg = client.complete([Message(role=Role.USER, content="2")])
    assert msg.content == "b"


def test_mock_client_json_mode():
    client = MockLLMClient(responses=["plain text"])
    msg = client.complete([Message(role=Role.USER, content="hi")], json_mode=True)
    data = json.loads(msg.content)
    assert "result" in data


def test_mock_client_stream():
    client = MockLLMClient(responses=["one two three"])
    tokens = list(client.stream([Message(role=Role.USER, content="hi")]))
    assert len(tokens) == 3


def test_mock_client_embed():
    client = MockLLMClient()
    embeddings = client.embed(["hello", "world"])
    assert len(embeddings) == 2
    assert len(embeddings[0]) == 8


def test_mock_client_tool_responses():
    from devai.core.models import ToolCall

    tool_msg = Message(
        role=Role.ASSISTANT,
        content="",
        tool_calls=[ToolCall(id="1", name="test", arguments={})],
    )
    client = MockLLMClient(tool_responses=[tool_msg], responses=["done"])
    msg = client.complete([Message(role=Role.USER, content="hi")])
    assert msg.tool_calls is not None


def test_mock_client_tracks_calls():
    client = MockLLMClient()
    messages = [Message(role=Role.USER, content="test")]
    client.complete(messages)
    assert len(client.calls) == 1


def test_llm_client_requires_api_key():
    config = DevAIConfig(api_key=None)
    with pytest.raises(LLMError, match="API key required"):
        LLMClient(config)
