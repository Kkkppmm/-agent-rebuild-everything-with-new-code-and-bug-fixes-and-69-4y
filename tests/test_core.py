"""Tests for devai core types and utilities."""

import pytest

from devai.types import Message, Role, ToolCall, ToolDefinition
from devai.prompts import PromptTemplate, chain_prompts
from devai.embeddings import cosine_similarity, euclidean_distance
from devai.memory import BufferMemory, WindowMemory


def test_message_to_dict():
  msg = Message(role=Role.USER, content="hello")
  d = msg.to_dict()
  assert d["role"] == "user"
  assert d["content"] == "hello"


def test_tool_call_to_dict():
  tc = ToolCall(id="call_1", name="search", arguments={"q": "test"})
  d = tc.to_dict()
  assert d["id"] == "call_1"
  assert d["function"]["name"] == "search"


def test_tool_definition_schema():
  tool = ToolDefinition(
    name="calc",
    description="Calculate",
    parameters={"type": "object", "properties": {}},
  )
  schema = tool.to_schema()
  assert schema["function"]["name"] == "calc"


def test_prompt_template_format():
  tmpl = PromptTemplate("Hello {name}, welcome to {place}")
  result = tmpl.format(name="Alice", place="DevAI")
  assert result == "Hello Alice, welcome to DevAI"


def test_chain_prompts():
  result = chain_prompts("Part 1", "Part 2", "")
  assert result == "Part 1\n\nPart 2"


def test_cosine_similarity():
  a = [1.0, 0.0, 0.0]
  b = [1.0, 0.0, 0.0]
  assert cosine_similarity(a, b) == 1.0


def test_euclidean_distance():
  a = [0.0, 0.0]
  b = [3.0, 4.0]
  assert euclidean_distance(a, b) == 5.0


def test_buffer_memory():
  mem = BufferMemory(system_prompt="Be helpful")
  mem.add(Message(role=Role.USER, content="hi"))
  messages = mem.get_messages()
  assert len(messages) == 2
  assert messages[0].role == Role.SYSTEM


def test_window_memory_truncation():
  mem = WindowMemory(max_messages=2)
  for i in range(5):
    mem.add(Message(role=Role.USER, content=f"msg {i}"))
  assert len(mem.get_messages()) == 2
