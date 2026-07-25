"""Tests for SequentialChain."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from devai.chains.chain import Chain
from devai.chains.sequential import SequentialChain
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message


@pytest.fixture
def mock_client():
  config = DevAIConfig(api_key="test-key")
  client = LLMClient(config)

  responses = [
    {"choices": [{"message": {"content": "Step 1 done"}, "finish_reason": "stop"}], "model": "test"},
    {"choices": [{"message": {"content": "Step 2 done"}, "finish_reason": "stop"}], "model": "test"},
  ]
  call_count = {"n": 0}

  def make_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = responses[min(call_count["n"], len(responses) - 1)]
    call_count["n"] += 1
    return mock_resp

  mock_http = MagicMock()
  mock_http.post.side_effect = lambda *a, **kw: make_response()
  client._client = mock_http

  mock_async_http = MagicMock()
  mock_async_http.post = MagicMock(side_effect=lambda *a, **kw: make_response())
  client._async_client = mock_async_http

  return client


def test_sequential_chain_runs_steps(mock_client):
  chain = SequentialChain([
    (Chain("Analyze: {input}", client=mock_client), "analysis"),
    (Chain("Summarize: {analysis}", client=mock_client), "summary"),
  ])
  result = chain.run(input="some code")
  assert result["analysis"] == "Step 1 done"
  assert result["summary"] == "Step 2 done"
  assert result["input"] == "some code"


@pytest.mark.asyncio
async def test_sequential_chain_arun(mock_client):
  mock_resp = MagicMock()
  mock_resp.status_code = 200
  mock_resp.json.return_value = {
    "choices": [{"message": {"content": "Step 1 done"}, "finish_reason": "stop"}],
    "model": "test",
  }
  mock_client._async_client.post = AsyncMock(return_value=mock_resp)

  chain = SequentialChain([
    (Chain("Task: {input}", client=mock_client), "output"),
  ])
  result = await chain.arun(input="hello")
  assert result["output"] == "Step 1 done"
