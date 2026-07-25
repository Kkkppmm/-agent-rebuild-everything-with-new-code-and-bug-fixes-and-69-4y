"""Tests for agents."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from devai.agents.agent import Agent
from devai.agents.coder_agent import CoderAgent
from devai.core.models import ChatResponse, Message, ToolCall
from devai.tools.registry import ToolRegistry


@pytest.fixture
def mock_client():
  client = MagicMock()
  return client


def test_agent_simple_response(mock_client):
  mock_client.chat.return_value = ChatResponse(content="Done!")
  agent = Agent(client=mock_client)
  result = agent.run("Hello")
  assert result.content == "Done!"
  assert result.iterations == 1


def test_agent_tool_loop(mock_client):
  tool_call = ToolCall(id="1", name="greet", arguments={"name": "World"})
  mock_client.chat.side_effect = [
    ChatResponse(content="", tool_calls=[tool_call]),
    ChatResponse(content="Greeted!"),
  ]

  registry = ToolRegistry()

  @registry.register()
  def greet(name: str) -> str:
    return f"Hello {name}"

  agent = Agent(client=mock_client, tools=registry)
  result = agent.run("Greet someone")
  assert result.content == "Greeted!"
  assert result.tool_calls_made == 1
  assert result.iterations == 2


def test_coder_agent_has_dev_tools(mock_client):
  mock_client.chat.return_value = ChatResponse(content="ok")
  agent = CoderAgent(client=mock_client)
  assert "read_file" in agent.tools
  assert "search_code" in agent.tools


@pytest.mark.asyncio
async def test_agent_async(mock_client):
  mock_client.achat = AsyncMock(return_value=ChatResponse(content="Async done"))
  agent = Agent(client=mock_client)
  result = await agent.arun("Hello")
  assert result.content == "Async done"
