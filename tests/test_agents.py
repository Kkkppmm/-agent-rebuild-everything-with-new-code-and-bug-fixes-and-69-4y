"""Tests for agents."""

from devai import MockLLMClient
from devai.agents import Agent, CoderAgent
from devai.tools import ToolRegistry, read_file


def test_agent_run():
    agent = Agent(client=MockLLMClient())
    result = agent.run("Hello")
    assert isinstance(result, str)
    assert agent.memory.message_count >= 2


def test_coder_agent():
    agent = CoderAgent(client=MockLLMClient())
    result = agent.run("Analyze the codebase")
    assert isinstance(result, str)


def test_agent_with_tools(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("x = 1")
    registry = ToolRegistry()
    registry.register(read_file)
    agent = Agent(
        client=MockLLMClient(responses=["", "Done"], enable_tool_calls=True),
        tools=registry,
    )
    result = agent.run(f"Read {f}")
    assert isinstance(result, str)
