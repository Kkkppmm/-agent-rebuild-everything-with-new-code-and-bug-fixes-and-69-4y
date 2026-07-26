"""Tests for core models."""

import pytest

from devai.core.models import Message, Role, Tool, ToolCall


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hello")
    assert msg.to_dict() == {"role": "user", "content": "hello"}


def test_message_with_tool_calls():
    tc = ToolCall(id="1", name="search", arguments={"q": "test"})
    msg = Message(role=Role.ASSISTANT, content="", tool_calls=[tc])
    d = msg.to_dict()
    assert d["tool_calls"][0]["name"] == "search"


def test_tool_openai_schema():
    tool = Tool(
        name="read_file",
        description="Read a file",
        parameters={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    schema = tool.to_openai_schema()
    assert schema["function"]["name"] == "read_file"


def test_role_enum():
    assert Role.USER.value == "user"
    assert Role("assistant") == Role.ASSISTANT
