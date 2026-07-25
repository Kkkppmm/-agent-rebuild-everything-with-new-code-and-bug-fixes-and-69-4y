"""Tests for devai client with mocked HTTP responses."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from devai import DevAI
from devai.exceptions import APIError, ConfigurationError
from devai.types import Message, Role


MOCK_CHAT_RESPONSE = {
  "id": "chatcmpl-test",
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help?",
      },
      "finish_reason": "stop",
    }
  ],
  "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
}

MOCK_EMBED_RESPONSE = {
  "model": "text-embedding-3-small",
  "data": [
    {"embedding": [0.1, 0.2, 0.3], "index": 0},
    {"embedding": [0.4, 0.5, 0.6], "index": 1},
  ],
  "usage": {"prompt_tokens": 5, "total_tokens": 5},
}


@pytest.fixture
def client():
  return DevAI(provider="openai", api_key="test-key")


@pytest.mark.asyncio
async def test_chat_string_prompt(client):
  mock_response = MagicMock()
  mock_response.status_code = 200
  mock_response.json.return_value = MOCK_CHAT_RESPONSE

  with patch("httpx.AsyncClient") as mock_client_cls:
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    response = await client.chat("Hello!")
    assert response.content == "Hello! How can I help?"
    assert response.model == "gpt-4o-mini"


@pytest.mark.asyncio
async def test_chat_with_messages(client):
  mock_response = MagicMock()
  mock_response.status_code = 200
  mock_response.json.return_value = MOCK_CHAT_RESPONSE

  with patch("httpx.AsyncClient") as mock_client_cls:
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    messages = [Message(role=Role.USER, content="Hi")]
    response = await client.chat(messages)
    assert response.content == "Hello! How can I help?"


@pytest.mark.asyncio
async def test_embed(client):
  mock_response = MagicMock()
  mock_response.status_code = 200
  mock_response.json.return_value = MOCK_EMBED_RESPONSE

  with patch("httpx.AsyncClient") as mock_client_cls:
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    response = await client.embed(["hello", "world"])
    assert len(response.embeddings) == 2
    assert response.embeddings[0] == [0.1, 0.2, 0.3]


@pytest.mark.asyncio
async def test_api_error(client):
  mock_response = MagicMock()
  mock_response.status_code = 401
  mock_response.text = "Unauthorized"

  with patch("httpx.AsyncClient") as mock_client_cls:
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    with pytest.raises(APIError) as exc_info:
      await client.chat("test")
    assert exc_info.value.status_code == 401


def test_unknown_provider():
  with pytest.raises(ConfigurationError, match="Unknown provider"):
    DevAI(provider="unknown", api_key="key")


def test_openai_requires_api_key():
  with pytest.raises(ConfigurationError, match="API key"):
    DevAI(provider="openai", api_key=None)
