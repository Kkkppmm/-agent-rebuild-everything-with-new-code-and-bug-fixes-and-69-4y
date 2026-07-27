"""Tests for LLM clients."""

import pytest

from devai.core.client import MockLLMClient
from devai.core.models import Message, Role, ToolDefinition


def test_mock_complete():
    client = MockLLMClient(responses=["Hello world"])
    msg = client.complete([Message(role=Role.USER, content="Hi")])
    assert msg.content == "Hello world"
    assert msg.role == "assistant"


def test_mock_cycles_responses():
    client = MockLLMClient(responses=["A", "B"])
    assert client.complete([Message(role=Role.USER, content="1")]).content == "A"
    assert client.complete([Message(role=Role.USER, content="2")]).content == "B"
    assert client.complete([Message(role=Role.USER, content="3")]).content == "A"


def test_mock_json_mode():
    client = MockLLMClient(responses=["result"])
    msg = client.complete([Message(role=Role.USER, content="Hi")], json_mode=True)
    assert '"result"' in msg.content
    assert '"status"' in msg.content


def test_mock_stream():
    client = MockLLMClient(responses=["one two three"])
    chunks = list(client.stream([Message(role=Role.USER, content="Hi")]))
    assert len(chunks) == 3


@pytest.mark.asyncio
async def test_mock_acomplete():
    client = MockLLMClient(responses=["async result"])
    msg = await client.acomplete([Message(role=Role.USER, content="Hi")])
    assert msg.content == "async result"


def test_mock_tool_calls():
    client = MockLLMClient(enable_tool_calls=True)
    tools = [ToolDefinition(name="read_file", description="Read")]
    msg = client.complete([Message(role=Role.USER, content="read")], tools=tools)
    assert msg.tool_calls is not None
    assert msg.tool_calls[0].name == "read_file"
