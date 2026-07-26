"""Tests for agents module."""

import pytest

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.core.exceptions import AgentError
from devai.tools.registry import ToolRegistry


class TestAgent:
    def test_simple_run(self):
        client = MockLLMClient(responses=["Done!"])
        agent = Agent(client=client)
        result = agent.run("Say hello")
        assert result == "Done!"

    def test_reset(self):
        client = MockLLMClient()
        agent = Agent(client=client)
        agent.run("task")
        assert len(agent.memory) > 0
        agent.reset()
        assert len(agent.memory) == 0

    @pytest.mark.asyncio
    async def test_arun(self):
        client = MockLLMClient(responses=["Async done"])
        agent = Agent(client=client)
        result = await agent.arun("task")
        assert result == "Async done"


class TestCoderAgent:
    def test_review(self):
        client = MockLLMClient(responses=["Looks good"])
        agent = CoderAgent(client=client)
        result = agent.review("def f(): pass")
        assert "Looks good" in result

    def test_has_code_tools(self):
        agent = CoderAgent(client=MockLLMClient())
        assert len(agent.tools) >= 5

    def test_explain(self):
        client = MockLLMClient(responses=["It adds numbers"])
        agent = CoderAgent(client=client)
        result = agent.explain("def add(a,b): return a+b")
        assert result
