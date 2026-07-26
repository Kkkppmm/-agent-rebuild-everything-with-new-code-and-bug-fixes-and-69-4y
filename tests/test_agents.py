"""Tests for agents module."""

import pytest

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.tools import create_default_registry


class TestAgent:
    def test_simple_run(self):
        client = MockLLMClient(responses=["Done!"])
        agent = Agent(client=client)
        result = agent.run("Hello")
        assert result == "Done!"
        assert len(agent.messages) == 3

    def test_tool_calling_loop(self):
        tc = MockLLMClient.make_tool_call(
            "explain_code", {"code": "x=1", "language": "python"}
        )
        client = MockLLMClient(
            responses=["", "Analysis complete."],
            tool_responses=[[tc], []],
        )
        agent = Agent(client=client, tools=create_default_registry())
        result = agent.run("Analyze x=1")
        assert "Analysis complete" in result

    def test_reset(self):
        client = MockLLMClient(responses=["ok"])
        agent = Agent(client=client)
        agent.run("hi")
        agent.reset()
        assert len(agent.messages) == 1

    @pytest.mark.asyncio
    async def test_async_run(self):
        client = MockLLMClient(responses=["async done"])
        agent = Agent(client=client)
        result = await agent.arun("go")
        assert result == "async done"


class TestCoderAgent:
    def test_review(self):
        client = MockLLMClient(responses=["Code looks fine."])
        agent = CoderAgent(client=client)
        result = agent.review("def f(): pass")
        assert "fine" in result

    def test_debug(self):
        client = MockLLMClient(responses=["Fix the type error."])
        agent = CoderAgent(client=client)
        result = agent.debug("x=1", "TypeError")
        assert "type error" in result.lower()

    def test_refactor(self):
        client = MockLLMClient(responses=["Refactored."])
        agent = CoderAgent(client=client)
        result = agent.refactor("def f(): pass", goal="performance")
        assert "Refactored" in result
