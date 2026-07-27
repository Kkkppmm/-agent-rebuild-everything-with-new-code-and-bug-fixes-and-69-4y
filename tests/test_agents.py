"""Tests for agents."""

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.tools import ToolRegistry, read_file


def test_agent_run():
  client = MockLLMClient()
  agent = Agent(client=client)
  result = agent.run("Review the auth module")
  assert result


def test_coder_agent():
  client = MockLLMClient()
  agent = CoderAgent(client=client)
  result = agent.run("Find all Python files")
  assert result


def test_agent_with_tools(tmp_path):
  f = tmp_path / "app.py"
  f.write_text("x = 1")

  registry = ToolRegistry()
  registry.register(read_file)

  client = MockLLMClient()
  agent = Agent(client=client, tools=registry)
  result = agent.run("Read the app.py file")
  assert result
