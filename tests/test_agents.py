"""Tests for agents."""

import json

from devai.agents import Agent, CoderAgent
from devai.core.models import ChatResponse, ToolCall
from devai.core.client import MockLLMClient
from devai.tools import ToolRegistry, read_file


class TestAgent:
    def test_simple_run(self):
        client = MockLLMClient(responses=["Task completed."])
        agent = Agent(client=client)
        result = agent.run("Do something")
        assert result == "Task completed."

    def test_tool_calling_loop(self):
        tool_response = ChatResponse(
            content="",
            tool_calls=[ToolCall(id="1", name="greet", arguments='{"name": "Dev"}')],
        )
        final_response = ChatResponse(content="Done greeting!")
        client = MockLLMClient(
            tool_responses=[tool_response, final_response],
        )

        registry = ToolRegistry()

        def greet(name: str) -> str:
            return f"Hello, {name}"

        registry.register(greet)
        agent = Agent(client=client, tools=registry)
        result = agent.run("Greet Dev")
        assert result == "Done greeting!"

    def test_coder_agent(self):
        client = MockLLMClient(responses=["Code looks good."])
        agent = CoderAgent(client=client)
        result = agent.review_file("main.py")
        assert "Code looks good" in result


class TestCoderAgent:
    def test_debug_error(self):
        client = MockLLMClient(responses=["Fix the type error."])
        agent = CoderAgent(client=client)
        result = agent.debug_error("TypeError: int + str")
        assert "type error" in result.lower()

    def test_explain_file(self):
        client = MockLLMClient(responses=["This file handles auth."])
        agent = CoderAgent(client=client)
        result = agent.explain_file("auth.py")
        assert "auth" in result.lower()
