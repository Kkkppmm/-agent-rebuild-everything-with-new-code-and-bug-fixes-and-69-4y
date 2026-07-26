"""Tests for agents."""

import json

from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import ToolCall
from devai.tools.registry import ToolRegistry


def test_agent_simple_response():
    client = MockLLMClient(responses=["The answer is 42."])
    agent = Agent(client=client)
    result = agent.run("What is the meaning of life?")
    assert "42" in result


def test_agent_with_tools():
    tc = ToolCall(id="1", name="explain_code", arguments=json.dumps({"code": "x=1"}))
    client = MockLLMClient(
        responses=["Based on analysis, x is assigned 1."],
        tool_responses=[[tc]],
    )
    registry = ToolRegistry()
    registry.register_builtins()
    agent = Agent(client=client, tools=registry)
    result = agent.run("Analyze this code")
    assert "analysis" in result.lower() or "1" in result


def test_agent_run_with_steps():
    client = MockLLMClient(responses=["Done."])
    agent = Agent(client=client)
    output = agent.run_with_steps("Hello")
    assert "answer" in output
    assert len(output["steps"]) >= 1


def test_coder_agent():
    client = MockLLMClient(responses=["Code looks good."])
    agent = CoderAgent(client=client)
    assert len(agent.tools) == 6


def test_coder_agent_review():
    client = MockLLMClient(responses=["No issues found."])
    agent = CoderAgent(client=client)
    result = agent.review("def foo(): pass")
    assert "issues" in result.lower() or "good" in result.lower()


def test_coder_agent_debug():
    client = MockLLMClient(responses=["Variable not defined."])
    agent = CoderAgent(client=client)
    result = agent.debug("NameError: x", "print(x)")
    assert len(result) > 0
