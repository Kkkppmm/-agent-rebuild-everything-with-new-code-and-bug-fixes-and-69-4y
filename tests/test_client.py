"""Tests for DevAI LLM client."""

import pytest

from devai.core.client import MockLLMClient
from devai.core.models import Message


def test_mock_client_basic():
    client = MockLLMClient(responses=["Hello!"])
    resp = client.chat([Message.user("Hi")])
    assert resp.content == "Hello!"
    assert resp.model == "mock-model"


def test_mock_client_multiple_responses():
    client = MockLLMClient(responses=["First", "Second"])
    assert client.chat([Message.user("1")]).content == "First"
    assert client.chat([Message.user("2")]).content == "Second"


def test_mock_client_json_mode():
    client = MockLLMClient(responses=["plain text"])
    resp = client.chat([Message.user("test")], json_mode=True)
    data = __import__("json").loads(resp.content)
    assert "result" in data


def test_mock_client_stream():
    client = MockLLMClient(responses=["hello world"])
    tokens = list(client.stream([Message.user("test")]))
    assert "".join(tokens).strip() == "hello world"


@pytest.mark.asyncio
async def test_mock_client_async():
    client = MockLLMClient(responses=["async response"])
    resp = await client.achat([Message.user("test")])
    assert resp.content == "async response"
