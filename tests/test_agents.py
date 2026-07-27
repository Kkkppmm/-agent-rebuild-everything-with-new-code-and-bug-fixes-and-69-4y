"""Tests for agents module."""

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import ToolCall
from devai.tools import ToolRegistry


def test_agent_simple_response():
  client = MockLLMClient(default_response="Task complete.")
  agent = Agent(client=client)
  result = agent.run("Say hello")
  assert result == "Task complete."


def test_agent_tool_calling_loop():
  tc = ToolCall(id="1", name="double", arguments={"x": 3})
  client = MockLLMClient(
    tool_responses=[[tc]],
    responses=["The result is 6."],
  )
  registry = ToolRegistry()
  registry.register("double", "Double", lambda x: str(x * 2), {
    "type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"],
  })
  agent = Agent(client=client, tools=registry, max_iterations=5)
  result = agent.run("Double 3")
  assert "6" in result


def test_coder_agent_default_tools():
  client = MockLLMClient(default_response="Analysis complete.")
  agent = CoderAgent(client=client)
  result = agent.run("Analyze my code")
  assert result == "Analysis complete."
  assert len(agent.tools.get_definitions()) >= 5
