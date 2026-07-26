"""Tests for agents."""

from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import Message, Role, ToolCall
from devai.tools.registry import ToolRegistry


def test_agent_simple():
    client = MockLLMClient(responses=["The answer is 42"])
    agent = Agent(client)
    result = agent.run("What is the answer?")
    assert result == "The answer is 42"


def test_agent_with_tools():
    registry = ToolRegistry()
    registry.register(
        "add",
        lambda a, b: str(a + b),
        "Add numbers",
        {
            "type": "object",
            "properties": {
                "a": {"type": "integer"},
                "b": {"type": "integer"},
            },
            "required": ["a", "b"],
        },
    )

    tc = ToolCall(id="1", name="add", arguments={"a": 2, "b": 3})
    client = MockLLMClient(
        responses=["let me calculate", "The sum is 5"],
        tool_calls=[tc],
    )
    # First response has tool call, second is final
    client.tool_calls = [tc]

    agent = Agent(client, tools=registry, max_iterations=5)

    # Manually simulate two-step: first call returns tool call
    def custom_complete(messages, tools=None, **kwargs):
        if client._call_count == 0:
            client._call_count += 1
            return Message(role=Role.ASSISTANT, content="", tool_calls=[tc])
        return Message(role=Role.ASSISTANT, content="The sum is 5")

    client.complete = custom_complete
    result = agent.run("What is 2+3?")
    assert "5" in result


def test_agent_reset():
    client = MockLLMClient()
    agent = Agent(client)
    agent.run("hello")
    assert len(agent.history) > 0
    agent.reset()
    assert len(agent.history) == 0


def test_coder_agent_tools():
    client = MockLLMClient(responses=["Analysis done"])
    agent = CoderAgent(client)
    assert len(agent.tools) == 6
