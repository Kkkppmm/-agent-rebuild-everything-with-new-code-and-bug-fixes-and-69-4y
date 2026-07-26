"""Tests for core models."""

from devai.core.models import Message, Role, Tool, ToolCall


def test_message_to_dict():
    msg = Message(role=Role.USER, content="hello")
    d = msg.to_dict()
    assert d["role"] == "user"
    assert d["content"] == "hello"


def test_tool_call_to_dict():
    tc = ToolCall(id="1", name="search", arguments={"q": "test"})
    d = tc.to_dict()
    assert d["function"]["name"] == "search"
    assert d["function"]["arguments"] == {"q": "test"}


def test_tool_to_dict():
    tool = Tool(
        name="read_file",
        description="Read a file",
        parameters={"type": "object", "properties": {}},
    )
    d = tool.to_dict()
    assert d["function"]["name"] == "read_file"
