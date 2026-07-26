"""Tests for DevAI models."""

from devai.core.models import Message, Response, ToolCall, ToolDefinition


def test_message_to_dict():
    msg = Message(role="user", content="hello")
    d = msg.to_dict()
    assert d == {"role": "user", "content": "hello"}


def test_message_with_tool_calls():
    tc = ToolCall(id="1", name="read_file", arguments='{"path": "test.py"}')
    msg = Message(role="assistant", tool_calls=[tc])
    d = msg.to_dict()
    assert d["role"] == "assistant"
    assert len(d["tool_calls"]) == 1


def test_message_from_dict():
    data = {"role": "user", "content": "test"}
    msg = Message.from_dict(data)
    assert msg.role == "user"
    assert msg.content == "test"


def test_tool_call_roundtrip():
    tc = ToolCall(id="abc", name="lint", arguments="{}")
    d = tc.to_dict()
    restored = ToolCall.from_dict(d)
    assert restored.name == "lint"


def test_tool_definition():
    td = ToolDefinition(
        name="search",
        description="Search code",
        parameters={"type": "object", "properties": {}},
    )
    d = td.to_dict()
    assert d["function"]["name"] == "search"


def test_response_has_tool_calls():
    r = Response(tool_calls=[ToolCall(id="1", name="t", arguments="{}")])
    assert r.has_tool_calls is True

    r2 = Response(content="hello")
    assert r2.has_tool_calls is False
