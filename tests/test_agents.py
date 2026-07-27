"""Tests for DevAI agents."""

from devai.agents import Agent, CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import ToolCall
from devai.tools import ToolRegistry, explain_code


class TestAgent:
    def test_run(self):
        client = MockLLMClient(responses=["Task completed."])
        agent = Agent(client=client)
        result = agent.run("Do something")
        assert result == "Task completed."
        assert len(agent.history) == 2

    def test_reset(self):
        client = MockLLMClient()
        agent = Agent(client=client)
        agent.run("test")
        agent.reset()
        assert len(agent.history) == 0


class TestCoderAgent:
    def test_run_without_tools(self):
        client = MockLLMClient(responses=["Done."])
        agent = CoderAgent(client=client)
        result = agent.run("Analyze this code")
        assert result == "Done."

    def test_run_with_tools(self):
        registry = ToolRegistry()
        registry.register(explain_code)
        client = MockLLMClient(responses=["Analysis complete."])
        agent = CoderAgent(client=client, tools=registry)
        tool_calls = [
            ToolCall(id="tc1", name="explain_code", arguments={"code": "def foo(): pass"}),
        ]
        result = agent.run_with_tools("Explain foo", tool_calls)
        assert result == "Analysis complete."

    def test_tool_registry_in_agent(self):
        registry = ToolRegistry()
        registry.register(explain_code)
        client = MockLLMClient()
        agent = CoderAgent(client=client, tools=registry)
        assert len(agent.tools) == 1
