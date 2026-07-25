"""Tests for Agent and Chain."""

from unittest.mock import MagicMock

import pytest

from devai.agents.agent import Agent, CoderAgent
from devai.chains.chain import Chain
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import AgentError
from devai.core.models import Message, ToolCall
from devai.prompts.template import PromptTemplate
from devai.tools.registry import ToolRegistry


def test_chain_run():
    mock_client = MagicMock(spec=LLMClient)
    mock_client.chat.return_value = Message.assistant("Review: looks good")

    chain = Chain(
        prompt=PromptTemplate("Review {code}"),
        client=mock_client,
    )
    result = chain.run(code="x=1")
    assert result == "Review: looks good"
    mock_client.chat.assert_called_once()


@pytest.mark.asyncio
async def test_chain_arun():
    mock_client = MagicMock(spec=LLMClient)

    async def async_chat(*args, **kwargs):
        return Message.assistant("async result")

    mock_client.achat = async_chat

    chain = Chain(prompt=PromptTemplate("Do {task}"), client=mock_client)
    result = await chain.arun(task="something")
    assert result == "async result"


def test_agent_run_no_tools():
    mock_client = MagicMock(spec=LLMClient)
    mock_client.chat.return_value = Message.assistant("The answer is 42")

    agent = Agent(client=mock_client)
    result = agent.run("What is the meaning of life?")
    assert result == "The answer is 42"
    assert len(agent.memory) == 2


def test_agent_run_with_tools():
    registry = ToolRegistry()

    @registry.register
    def double(n: int) -> int:
        """Double a number."""
        return n * 2

    mock_client = MagicMock(spec=LLMClient)

    tool_response = Message.assistant(
        tool_calls=[ToolCall(id="c1", name="double", arguments={"n": 5})]
    )
    final_response = Message.assistant("The result is 10")
    mock_client.chat.side_effect = [tool_response, final_response]

    agent = Agent(client=mock_client, tools=registry)
    result = agent.run("Double 5")
    assert result == "The result is 10"
    assert mock_client.chat.call_count == 2


def test_agent_reset():
    mock_client = MagicMock(spec=LLMClient)
    mock_client.chat.return_value = Message.assistant("ok")
    agent = Agent(client=mock_client)
    agent.run("hi")
    assert len(agent.memory) == 2
    agent.reset()
    assert len(agent.memory) == 0


def test_agent_max_rounds_raises():
    mock_client = MagicMock(spec=LLMClient)
    registry = ToolRegistry()

    @registry.register
    def noop() -> str:
        return "ok"

    tool_response = Message.assistant(
        tool_calls=[ToolCall(id="c1", name="noop", arguments={})]
    )
    mock_client.chat.return_value = tool_response

    config = DevAIConfig(api_key="test", max_tool_rounds=2)
    agent = Agent(client=mock_client, config=config, tools=registry)

    with pytest.raises(AgentError, match="max tool rounds"):
        agent.run("loop forever")


def test_coder_agent_has_tools():
    mock_client = MagicMock(spec=LLMClient)
    coder = CoderAgent(client=mock_client)
    assert len(coder.tools) == 6
    assert "explain_code" in coder.tools
    assert "lint_python" in coder.tools
