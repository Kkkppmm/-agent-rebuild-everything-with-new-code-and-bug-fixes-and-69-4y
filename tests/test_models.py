"""Tests for DevAI core models."""

import json

import pytest

from devai.core.models import Message, Role, ToolCall, ToolDefinition


def test_message_system_factory():
  msg = Message.system("You are helpful.")
  assert msg.role == Role.SYSTEM
  assert msg.content == "You are helpful."


def test_message_to_api_dict():
  msg = Message.user("Hello")
  data = msg.to_api_dict()
  assert data == {"role": "user", "content": "Hello"}


def test_message_with_tool_calls():
  tc = ToolCall(id="call_1", name="read_file", arguments={"path": "main.py"})
  msg = Message.assistant("", tool_calls=[tc])
  data = msg.to_api_dict()
  assert data["role"] == "assistant"
  assert len(data["tool_calls"]) == 1
  assert data["tool_calls"][0]["function"]["name"] == "read_file"
  args = json.loads(data["tool_calls"][0]["function"]["arguments"])
  assert args["path"] == "main.py"


def test_tool_definition_to_api_dict():
  tool = ToolDefinition(
    name="search",
    description="Search code",
    parameters={"type": "object", "properties": {}},
  )
  data = tool.to_api_dict()
  assert data["type"] == "function"
  assert data["function"]["name"] == "search"
