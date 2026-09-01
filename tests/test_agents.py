"""Tests for DevAI agents."""

import json

from devai.agents import Agent, CoderAgent
from devai.core import MockLLMClient
from devai.tools import ToolRegistry


def _greet_tool(name: str) -> str:
    """Greet someone by name."""
    return f"Hello, {name}!"


class TestAgent:
    def test_simple_response(self):
        client = MockLLMClient(default_response="Task completed.")
        agent = Agent(client=client)
        result = agent.run("Do something")
        assert result == "Task completed."

    def test_with_tools(self):
        tool_calls = [
            {
                "id": "call_1",
                "function": {
                    "name": "greet",
                    "arguments": json.dumps({"name": "Dev"}),
                },
            }
        ]
        client = MockLLMClient(
            responses=[
                json.dumps({"tool_calls": tool_calls}),
                "Greeted Dev successfully.",
            ]
        )
        registry = ToolRegistry()
        registry.register(_greet_tool, name="greet")
        agent = Agent(client=client, tools=registry)
        result = agent.run("Greet Dev")
        assert "Greeted" in result


class TestCoderAgent:
    def test_default_system_prompt(self):
        client = MockLLMClient(default_response="Done")
        agent = CoderAgent(client=client)
        assert "software engineer" in agent.system_prompt.lower()

    def test_run_task(self):
        client = MockLLMClient(default_response="Refactored the module.")
        agent = CoderAgent(client=client)
        result = agent.run("Refactor auth module")
        assert "Refactored" in result
