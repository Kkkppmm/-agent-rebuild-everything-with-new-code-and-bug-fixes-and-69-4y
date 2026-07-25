"""Tests for DevAI agents."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from devai.agents.agent import Agent
from devai.agents.coder import CoderAgent
from devai.core.config import DevAIConfig
from devai.core.models import CompletionResponse, ToolCall, Message, Role
from devai.core.exceptions import AgentError
from devai.tools.registry import ToolRegistry


class TestAgent:
    @pytest.fixture
    def config(self):
        return DevAIConfig(api_key="test-key")

    @pytest.mark.asyncio
    async def test_simple_response(self, config):
        agent = Agent(config=config)
        agent.client.chat = AsyncMock(
            return_value=CompletionResponse(content="Task done!", finish_reason="stop")
        )
        result = await agent.run("Do something")
        assert result == "Task done!"
        assert len(agent.memory) == 2

    @pytest.mark.asyncio
    async def test_tool_calling_loop(self, config):
        registry = ToolRegistry()

        @registry.register()
        def get_data(key: str) -> str:
            return f"value:{key}"

        agent = Agent(config=config, tools=registry, max_iterations=5)
        agent.client.chat = AsyncMock(side_effect=[
            CompletionResponse(
                content="",
                tool_calls=[ToolCall(id="1", name="get_data", arguments={"key": "test"})],
                finish_reason="tool_calls",
            ),
            CompletionResponse(content="The value is value:test", finish_reason="stop"),
        ])
        result = await agent.run("Get the data")
        assert "value:test" in result

    @pytest.mark.asyncio
    async def test_max_iterations_exceeded(self, config):
        registry = ToolRegistry()

        @registry.register()
        def x() -> str:
            return "ok"

        agent = Agent(config=config, tools=registry, max_iterations=2)
        agent.client.chat = AsyncMock(
            return_value=CompletionResponse(
                content="",
                tool_calls=[ToolCall(id="1", name="x", arguments={})],
                finish_reason="tool_calls",
            )
        )
        with pytest.raises(AgentError):
            await agent.run("loop forever")


class TestCoderAgent:
    @pytest.fixture
    def config(self):
        return DevAIConfig(api_key="test-key")

    def test_has_default_tools(self, config):
        agent = CoderAgent(config=config)
        assert len(agent.tools) == 6

    @pytest.mark.asyncio
    async def test_review(self, config):
        agent = CoderAgent(config=config)
        agent.client.chat = AsyncMock(
            return_value=CompletionResponse(content="Looks good!", finish_reason="stop")
        )
        result = await agent.review("def f(): pass")
        assert result == "Looks good!"

    @pytest.mark.asyncio
    async def test_debug(self, config):
        agent = CoderAgent(config=config)
        agent.client.chat = AsyncMock(
            return_value=CompletionResponse(content="Fix: initialize x", finish_reason="stop")
        )
        result = await agent.debug("print(x)", "NameError: x")
        assert "Fix" in result
