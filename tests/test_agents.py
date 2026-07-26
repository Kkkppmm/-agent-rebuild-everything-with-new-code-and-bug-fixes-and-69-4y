"""Tests for DevAI agents."""

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.tools.registry import ToolRegistry


def test_agent_basic():
    client = MockLLMClient(responses=["I can help with that."])
    agent = Agent(client)
    result = agent.run("Help me debug this code")
    assert "help" in result.lower()


def test_agent_reset():
    client = MockLLMClient(responses=["response"])
    agent = Agent(client)
    agent.run("hello")
    assert len(agent.memory) > 1
    agent.reset()
    assert len(agent.memory) == 1  # system message only


def test_coder_agent():
    client = MockLLMClient(responses=["Analysis complete."])
    agent = CoderAgent(client)
    assert agent.tools is not None
    assert len(agent.tools) >= 6
    result = agent.run("What tools do you have?")
    assert result
