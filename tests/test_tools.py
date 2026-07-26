"""Tests for tool registry."""

import pytest

from devai.core.exceptions import ToolError
from devai.tools.registry import ToolRegistry


def test_register_and_execute():
    registry = ToolRegistry()

    @registry.register(description="Add two numbers")
    def add(a: int, b: int) -> int:
        return a + b

    assert "add" in registry
    assert registry.execute("add", {"a": 2, "b": 3}) == "5"


def test_unknown_tool():
    registry = ToolRegistry()
    with pytest.raises(ToolError, match="Unknown tool"):
        registry.execute("missing", {})


def test_tool_schema():
    registry = ToolRegistry()

    @registry.register(description="Greet someone")
    def greet(name: str) -> str:
        return f"Hello {name}"

    tools = registry.get_tools()
    assert len(tools) == 1
    assert tools[0].name == "greet"


def test_tool_failure():
    registry = ToolRegistry()

    @registry.register()
    def fail() -> None:
        raise ValueError("boom")

    with pytest.raises(ToolError, match="failed"):
        registry.execute("fail", {})
