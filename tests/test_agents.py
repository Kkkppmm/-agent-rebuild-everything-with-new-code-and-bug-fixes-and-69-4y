"""Tests for agents."""

import json

from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import Message, Role, ToolCall
from devai.tools.registry import ToolRegistry


class TestAgent:
    def test_simple_run(self):
        llm = MockLLMClient(responses=["Task completed successfully."])
        agent = Agent(llm)
        result = agent.run("Do something")
        assert "completed" in result

    def test_tool_calling_loop(self):
        tool_response = Message(
            role=Role.ASSISTANT,
            content="",
            tool_calls=[ToolCall(id="1", name="greet", arguments={"name": "Dev"})],
        )
        final_response = Message(role=Role.ASSISTANT, content="Done: Hello Dev")

        llm = MockLLMClient(
            responses=["fallback"],
            tool_responses=[tool_response, final_response],
        )
        registry = ToolRegistry()

        @registry.register()
        def greet(name: str) -> str:
            return f"Hello {name}"

        agent = Agent(llm, tools=registry)
        result = agent.run("Greet someone")
        assert "Done" in result


class TestCoderAgent:
    def test_review(self):
        llm = MockLLMClient(responses=["Code looks clean."])
        agent = CoderAgent(llm)
        result = agent.review("def add(a, b): return a + b")
        assert "clean" in result

    def test_explain(self):
        llm = MockLLMClient(responses=["This adds two numbers."])
        agent = CoderAgent(llm)
        result = agent.explain("def add(a, b): return a + b")
        assert "numbers" in result

    def test_debug(self):
        llm = MockLLMClient(responses=["Variable x is not defined."])
        agent = CoderAgent(llm)
        result = agent.debug("NameError: x", code="print(x)")
        assert "defined" in result
