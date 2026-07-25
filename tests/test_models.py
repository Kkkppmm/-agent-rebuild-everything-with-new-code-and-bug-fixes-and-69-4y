"""Tests for DevAI core models."""

import json

from devai.core.models import Message, Role, ToolCall, ToolDefinition


def test_message_system_factory():
    msg = Message.system("hello")
    assert msg.role == Role.SYSTEM
    assert msg.content == "hello"


def test_message_to_api():
    msg = Message.user("test")
    api = msg.to_api()
    assert api == {"role": "user", "content": "test"}


def test_tool_call_roundtrip():
    api_data = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "search", "arguments": '{"query": "foo"}'},
    }
    tc = ToolCall.from_api(api_data)
    assert tc.name == "search"
    assert tc.arguments == {"query": "foo"}
    assert tc.to_api()["function"]["name"] == "search"


def test_tool_definition_to_api():
    td = ToolDefinition(name="calc", description="Add numbers", parameters={
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
        "required": ["a", "b"],
    })
    api = td.to_api()
    assert api["function"]["name"] == "calc"


def test_assistant_with_tool_calls():
    tc = ToolCall(id="1", name="fn", arguments={"x": 1})
    msg = Message.assistant(tool_calls=[tc])
    api = msg.to_api()
    assert "tool_calls" in api
    args = json.loads(api["tool_calls"][0]["function"]["arguments"])
    assert args["x"] == 1
