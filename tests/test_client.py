"""Tests for MockLLMClient."""

import pytest

from devai.core.client import MockLLMClient
from devai.core.models import Message, Role


def test_mock_complete():
  client = MockLLMClient()
  messages = [Message(role=Role.USER, content="review this code")]
  result = client.complete(messages)
  assert result.content
  assert result.model == "mock"
  assert len(client.call_history) == 1


def test_mock_custom_responses():
  client = MockLLMClient(responses={"review": "Looks good!"})
  messages = [Message(role=Role.USER, content="please review this")]
  result = client.complete(messages)
  assert result.content == "Looks good!"


def test_mock_stream():
  client = MockLLMClient()
  messages = [Message(role=Role.USER, content="hello")]
  chunks = list(client.stream(messages))
  full = "".join(chunks)
  assert "Mock response" in full


@pytest.mark.asyncio
async def test_mock_acomplete():
  client = MockLLMClient()
  messages = [Message(role=Role.USER, content="test")]
  result = await client.acomplete(messages)
  assert result.content
