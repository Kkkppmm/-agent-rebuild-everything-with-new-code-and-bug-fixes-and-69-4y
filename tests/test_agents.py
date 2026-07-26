"""Tests for agents."""

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import Message, Role, ToolCall
from devai.tools.registry import ToolRegistry


def test_agent_basic():
    client = MockLLMClient(responses=["I can help with that."])
    agent = Agent(client)
    result = agent.run("How do I sort a list in Python?")
    assert "help" in result.lower()


def test_agent_conversation_history():
    client = MockLLMClient(responses=["First", "Second"])
    agent = Agent(client)
    agent.run("Q1")
    agent.run("Q2")
    assert len(agent.messages) == 4  # 2 user + 2 assistant


def test_agent_reset():
    client = MockLLMClient(responses=["Hi"])
    agent = Agent(client)
    agent.run("Hello")
    agent.reset()
    assert len(agent.messages) == 0


def test_coder_agent():
    client = MockLLMClient(responses=["This function adds two numbers."])
    agent = CoderAgent(client)
    result = agent.explain("def add(a, b): return a + b")
    assert len(result) > 0


def test_coder_agent_review():
    client = MockLLMClient(responses=["Code looks clean."])
    agent = CoderAgent(client)
    result = agent.review("x = 1")
    assert "clean" in result.lower()


def test_coder_agent_debug():
    client = MockLLMClient(responses=["Fix the typo in variable name."])
    agent = CoderAgent(client)
    result = agent.debug("print(x)", "NameError: x")
    assert "typo" in result.lower()


def test_coder_agent_refactor():
    client = MockLLMClient(responses=["Use a list comprehension."])
    agent = CoderAgent(client)
    result = agent.refactor("[x for x in range(10)]")
    assert "comprehension" in result.lower()
