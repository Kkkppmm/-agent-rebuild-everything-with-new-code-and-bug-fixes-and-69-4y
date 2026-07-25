"""Tests for devai tools registry."""

import pytest

from devai.tools import ToolRegistry
from devai.types import ToolCall
from devai.exceptions import ToolExecutionError


def test_register_tool():
  registry = ToolRegistry()

  @registry.tool(description="Add two numbers")
  def add(a: int, b: int) -> int:
    return a + b

  tools = registry.list_tools()
  assert len(tools) == 1
  assert tools[0].name == "add"
  assert "integer" in str(tools[0].parameters)


@pytest.mark.asyncio
async def test_execute_tool():
  registry = ToolRegistry()

  @registry.tool()
  def greet(name: str) -> str:
    return f"Hello, {name}!"

  result = await registry.execute(ToolCall(id="1", name="greet", arguments={"name": "World"}))
  assert result == "Hello, World!"


@pytest.mark.asyncio
async def test_execute_async_tool():
  registry = ToolRegistry()

  @registry.tool()
  async def async_add(a: int, b: int) -> int:
    return a + b

  result = await registry.execute(ToolCall(id="1", name="async_add", arguments={"a": 2, "b": 3}))
  assert result == "5"


@pytest.mark.asyncio
async def test_execute_missing_tool():
  registry = ToolRegistry()
  with pytest.raises(ToolExecutionError, match="not found"):
    await registry.execute(ToolCall(id="1", name="missing", arguments={}))


@pytest.mark.asyncio
async def test_execute_all():
  registry = ToolRegistry()

  @registry.tool()
  def double(x: int) -> int:
    return x * 2

  calls = [ToolCall(id="1", name="double", arguments={"x": 5})]
  messages = await registry.execute_all(calls)
  assert len(messages) == 1
  assert messages[0].content == "10"
