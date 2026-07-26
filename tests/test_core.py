"""Tests for DevAI core module."""

import pytest

from devai import DevAIConfig, Message, MockLLMClient, Role
from devai.core.models import Tool, ToolCall
from devai.core.retry import with_retries


def test_config_defaults():
    config = DevAIConfig(api_key="test-key")
    assert config.model == "gpt-4o-mini"
    assert config.temperature == 0.2
    assert config.max_retries == 3


def test_config_with_overrides():
    config = DevAIConfig(api_key="k").with_overrides(temperature=0.9, model="gpt-4")
    assert config.temperature == 0.9
    assert config.model == "gpt-4"
    assert config.api_key == "k"


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hello")
    assert msg.to_dict() == {"role": "user", "content": "hello"}


def test_tool_openai_schema():
    tool = Tool(name="search", description="Search code", parameters={"type": "object"})
    schema = tool.to_openai_schema()
    assert schema["function"]["name"] == "search"


def test_mock_client_cycles_responses():
    client = MockLLMClient(responses=["a", "b"])
    assert client.chat("hi") == "a"
    assert client.chat("hi") == "b"
    assert client.chat("hi") == "a"


def test_mock_client_stream():
    client = MockLLMClient(responses=["abc"])
    tokens = list(client.stream("hi"))
    assert "".join(tokens) == "abc"


def test_mock_client_tool_calls():
    calls = [ToolCall(id="1", name="lint", arguments={"code": "x"})]
    client = MockLLMClient(tool_responses=[(None, calls)])
    content, tool_calls = client.chat_with_tools([], [])
    assert content is None
    assert len(tool_calls) == 1
    assert tool_calls[0].name == "lint"


def test_with_retries_succeeds():
    attempts = {"n": 0}

    def fn():
        attempts["n"] += 1
        if attempts["n"] < 2:
            from devai.core.exceptions import RateLimitError

            raise RateLimitError("retry")
        return "ok"

    assert with_retries(fn, max_retries=3) == "ok"


def test_with_retries_exhausted():
    from devai.core.exceptions import RateLimitError

    def fn():
        raise RateLimitError("fail")

    with pytest.raises(RateLimitError):
        with_retries(fn, max_retries=1)
