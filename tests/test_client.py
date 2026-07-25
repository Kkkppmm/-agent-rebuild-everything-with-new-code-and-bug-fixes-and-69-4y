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
  client.config.max_retries = 0

  with pytest.raises(LLMError):
    client.chat([Message.user("Hi")])


def test_chat_retries_on_rate_limit(config, mock_response):
  client = LLMClient(config)
  client.config.max_retries = 2
  mock_http = MagicMock()

  rate_limited = MagicMock()
  rate_limited.status_code = 429
  rate_limited.text = "rate limited"

  success = MagicMock()
  success.status_code = 200
  success.json.return_value = mock_response

  mock_http.post.side_effect = [rate_limited, success]
  client._client = mock_http

  with patch("devai.core.client.time.sleep"):
    result = client.chat([Message.user("Hi")])

  assert result.content == "Hello!"
  assert mock_http.post.call_count == 2


def test_chat_json(config):
  client = LLMClient(config)
  mock_http = MagicMock()
  mock_resp = MagicMock()
  mock_resp.status_code = 200
  mock_resp.json.return_value = {
    "choices": [{
      "message": {"role": "assistant", "content": '{"name": "test", "value": 42}'},
      "finish_reason": "stop",
    }],
    "model": "gpt-4o-mini",
  }
  mock_http.post.return_value = mock_resp
  client._client = mock_http

  result = client.chat_json([Message.user("Return JSON")])
  assert result == {"name": "test", "value": 42}

  payload = mock_http.post.call_args[1]["json"]
  assert payload["response_format"] == {"type": "json_object"}


def test_chat_json_invalid(config):
  client = LLMClient(config)
  mock_http = MagicMock()
  mock_resp = MagicMock()
  mock_resp.status_code = 200
  mock_resp.json.return_value = {
    "choices": [{
      "message": {"role": "assistant", "content": "not json"},
      "finish_reason": "stop",
    }],
    "model": "gpt-4o-mini",
  }
  mock_http.post.return_value = mock_resp
  client._client = mock_http

  with pytest.raises(LLMError, match="Failed to parse JSON"):
    client.chat_json([Message.user("Return JSON")])
