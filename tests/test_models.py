"""Tests for DevAI core models."""

from devai.core.models import Message, Role, ToolCall, ToolDefinition


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hello")
    d = msg.to_dict()
    assert d["role"] == "user"
    assert d["content"] == "hello"


def test_tool_definition():
    td = ToolDefinition(name="read_file", description="Read a file", parameters={"type": "object"})
    d = td.to_dict()
    assert d["function"]["name"] == "read_file"


def test_tool_call_to_dict():
    tc = ToolCall(id="call_1", name="search", arguments={"pattern": "foo"})
    d = tc.to_dict()
    assert d["function"]["name"] == "search"
