"""Tests for tool registry."""

import json

import pytest

from devai.core.exceptions import ToolExecutionError
from devai.tools.registry import ToolRegistry


def test_register_and_execute():
  registry = ToolRegistry()

  @registry.register(description="Add two numbers")
  def add(a: int, b: int) -> int:
    return a + b

  result = registry.execute("add", {"a": 2, "b": 3})
  assert result == "5"


def test_get_definitions():
  registry = ToolRegistry()

  @registry.register()
  def greet(name: str) -> str:
    """Say hello."""
    return f"Hello {name}"

  defs = registry.get_definitions()
  assert len(defs) == 1
  assert defs[0].name == "greet"
  assert "name" in defs[0].parameters["properties"]


def test_unknown_tool():
  registry = ToolRegistry()
  with pytest.raises(ToolExecutionError, match="Unknown tool"):
    registry.execute("missing", {})


def test_tool_failure():
  registry = ToolRegistry()

  @registry.register()
  def fail() -> None:
    raise RuntimeError("boom")

  with pytest.raises(ToolExecutionError, match="boom"):
    registry.execute("fail", {})
