"""Tests for LLM clients."""

import pytest
from devai.core.client import MockLLMClient
from devai.core.models import Message, Role, ToolCall


def test_mock_complete():
    client = MockLLMClient(responses=["Hello", "World"])
    msg = client.complete([Message(role=Role.USER, content="Hi")])
    assert msg.content == "Hello"
    assert msg.role == Role.ASSISTANT


def test_mock_multiple_calls():
    client = MockLLMClient(responses=["first", "second"])
    client.complete([Message(role=Role.USER, content="1")])
    msg = client.complete([Message(role=Role.USER, content="2")])
    assert msg.content == "second"


def test_mock_stream():
    client = MockLLMClient(responses=["abc"])
    chunks = list(client.stream([Message(role=Role.USER, content="Hi")]))
    assert "".join(chunks) == "abc"


def test_mock_records_calls():
    client = MockLLMClient()
    client.complete([Message(role=Role.USER, content="test")])
    assert len(client.calls) == 1


def test_mock_with_tool_calls():
    tc = ToolCall(id="1", name="search", arguments={"q": "x"})
    client = MockLLMClient(responses=["using tool"], tool_calls=[tc])
    msg = client.complete([Message(role=Role.USER, content="search")])
    assert msg.tool_calls is not None
    assert msg.tool_calls[0].name == "search"


@pytest.mark.asyncio
async def test_mock_acomplete():
    client = MockLLMClient(responses=["async"])
    msg = await client.acomplete([Message(role=Role.USER, content="Hi")])
    assert msg.content == "async"
