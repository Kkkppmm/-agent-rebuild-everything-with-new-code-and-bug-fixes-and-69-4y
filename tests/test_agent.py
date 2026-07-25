"""Tests for devai agent loop."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from devai import DevAI, Agent
from devai.tools import ToolRegistry
from devai.types import ChatResponse, ToolCall


@pytest.fixture
def client():
  return DevAI(provider="openai", api_key="test-key")


@pytest.mark.asyncio
async def test_agent_simple_response(client):
  response = ChatResponse(content="The answer is 42.")
  with patch.object(client.provider, "chat", new_callable=AsyncMock, return_value=response):
    agent = Agent(client)
    result = await agent.run("What is the meaning of life?")
    assert result.response.content == "The answer is 42."
    assert result.iterations == 1
    assert result.tool_calls_made == 0


@pytest.mark.asyncio
async def test_agent_with_tools(client):
  registry = ToolRegistry()

  @registry.tool(description="Multiply two numbers")
  def multiply(a: int, b: int) -> int:
    return a * b

  tool_response = ChatResponse(
    content="",
    tool_calls=[ToolCall(id="call_1", name="multiply", arguments={"a": 6, "b": 7})],
  )
  final_response = ChatResponse(content="6 times 7 is 42.")

  with patch.object(
    client.provider,
    "chat",
    new_callable=AsyncMock,
    side_effect=[tool_response, final_response],
  ):
    agent = Agent(client, tools=registry)
    result = await agent.run("What is 6 * 7?")
    assert result.response.content == "6 times 7 is 42."
    assert result.tool_calls_made == 1
    assert result.iterations == 2
