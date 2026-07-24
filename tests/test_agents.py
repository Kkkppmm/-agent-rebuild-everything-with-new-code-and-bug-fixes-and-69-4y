"""Tests for agents."""

from devai import DevAIConfig, MockLLMClient
from devai.agents import Agent, CoderAgent
from devai.core.models import ToolCall
from devai.tools import ToolRegistry


def test_agent_simple_response():
    client = MockLLMClient(responses=["Done."])
    agent = Agent(client, DevAIConfig())
    result = agent.run("Hello")
    assert result == "Done."
    assert len(agent.history) == 2


def test_agent_with_tool_calls():
    tool_call = ToolCall(id="1", name="explain_code", arguments={"code": "x=1"})
    client = MockLLMClient(
        tool_responses=[
            (None, [tool_call]),
            ("Analysis complete.", []),
        ]
    )
    agent = Agent(client, DevAIConfig(), tools=ToolRegistry())
    registry = ToolRegistry()

    @registry.register
    def explain_code(code: str) -> str:
        return f"Explained: {code}"

    agent.tools = registry
    result = agent.run("Explain x=1")
    assert "Analysis complete" in result


def test_agent_reset():
    client = MockLLMClient(responses=["ok"])
    agent = Agent(client, DevAIConfig())
    agent.run("hi")
    agent.reset()
    assert len(agent.history) == 0


def test_coder_agent_review():
    client = MockLLMClient(responses=["Looks good."])
    agent = CoderAgent(client, DevAIConfig())
    result = agent.review("def add(a,b): return a+b")
    assert "Looks good" in result


def test_coder_agent_debug():
    client = MockLLMClient(responses=["Fix the typo."])
    agent = CoderAgent(client, DevAIConfig())
    result = agent.debug("x = y", "NameError: y is not defined")
    assert "Fix the typo" in result
