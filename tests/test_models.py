"""Tests for DevAI core models."""

import json

import pytest

from devai.core.models import Message, Role, Tool, ToolCall


def test_message_system():
    msg = Message.system("hello")
    assert msg.role == Role.SYSTEM
    assert msg.content == "hello"


def test_message_to_dict():
    msg = Message.user("test")
    d = msg.to_dict()
    assert d == {"role": "user", "content": "test"}


def test_message_with_tool_calls():
    tc = ToolCall(id="1", name="search", arguments={"q": "test"})
    msg = Message.assistant(tool_calls=[tc])
    d = msg.to_dict()
    assert d["role"] == "assistant"
    assert len(d["tool_calls"]) == 1
    assert d["tool_calls"][0]["function"]["name"] == "search"


def test_tool_call_from_raw():
    raw = {"id": "abc", "name": "read_file", "arguments": '{"path": "/tmp"}'}
    tc = ToolCall.from_raw(raw)
    assert tc.id == "abc"
    assert tc.arguments == {"path": "/tmp"}


def test_tool_openai_schema():
    tool = Tool(name="test", description="A test tool")
    schema = tool.to_openai_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "test"
