"""Tests for LLM client (mocked)."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigurationError, LLMError, RateLimitError
from devai.core.models import Message


@pytest.fixture
def config():
  return DevAIConfig(api_key="test-key", base_url="https://api.example.com/v1")


@pytest.fixture
def mock_response():
  return {
    "choices": [{
      "message": {"role": "assistant", "content": "Hello!"},
      "finish_reason": "stop",
    }],
    "model": "gpt-4o-mini",
    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
  }


def test_missing_api_key():
  client = LLMClient(DevAIConfig(api_key=""))
  with pytest.raises(ConfigurationError):
    client._headers()


def test_chat(config, mock_response):
  client = LLMClient(config)
  mock_http = MagicMock()
  mock_resp = MagicMock()
  mock_resp.status_code = 200
  mock_resp.json.return_value = mock_response
  mock_http.post.return_value = mock_resp
  client._client = mock_http

  result = client.chat([Message.user("Hi")])
  assert result.content == "Hello!"
  assert result.model == "gpt-4o-mini"


def test_chat_rate_limit(config):
  client = LLMClient(config)
  mock_http = MagicMock()
  mock_resp = MagicMock()
  mock_resp.status_code = 429
  mock_resp.text = "rate limited"
  mock_http.post.return_value = mock_resp
  client._client = mock_http

  with pytest.raises(RateLimitError):
    client.chat([Message.user("Hi")])


def test_chat_api_error(config):
  client = LLMClient(config)
  mock_http = MagicMock()
  mock_resp = MagicMock()
  mock_resp.status_code = 500
  mock_resp.text = "server error"
  mock_http.post.return_value = mock_resp
  client._client = mock_http

  with pytest.raises(LLMError):
    client.chat([Message.user("Hi")])
