"""Tests for agents."""

from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import Message, Role, ToolCall
from devai.tools.registry import ToolRegistry


def test_agent_simple_response():
    client = MockLLMClient(responses=["The answer is 42"])
    agent = Agent(client)
    result = agent.run("What is the meaning of life?")
    assert "42" in result


def test_agent_with_tools():
    tool_call = Message(
        role=Role.ASSISTANT,
        content="",
        tool_calls=[ToolCall(id="1", name="explain_code", arguments={"code": "x=1"})],
    )
    final = Message(role=Role.ASSISTANT, content="Code defines x as 1")
    client = MockLLMClient(tool_responses=[tool_call, final])

    registry = ToolRegistry()
    registry.register("explain_code", lambda code: f"Lines: 1", "Explain code")

    agent = Agent(client, tools=registry)
    result = agent.run("Explain this code: x=1")
    assert "x" in result.lower() or "1" in result


def test_agent_reset():
    client = MockLLMClient(responses=["ok"])
    agent = Agent(client)
    agent.run("hello")
    agent.reset()
    assert len(agent.messages) == 0


def test_coder_agent_review():
    client = MockLLMClient(responses=["Looks good"])
    agent = CoderAgent(client)
    result = agent.review("def foo(): pass")
    assert "Looks good" in result


def test_coder_agent_has_tools():
    client = MockLLMClient(responses=["done"])
    agent = CoderAgent(client)
    assert len(agent.tools) == 6
