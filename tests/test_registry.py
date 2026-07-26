"""Tests for tool registry."""

import pytest
from devai.tools.registry import ToolRegistry
from devai.core.exceptions import ToolError


def test_register_and_execute():
    registry = ToolRegistry()
    registry.register(
        "greet",
        lambda name: f"Hello, {name}!",
        "Greet someone",
        {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    )
    result = registry.execute("greet", {"name": "World"})
    assert result == "Hello, World!"


def test_get_tools():
    registry = ToolRegistry()
    registry.register("fn", lambda: "ok", "desc", {"type": "object"})
    tools = registry.get_tools()
    assert len(tools) == 1
    assert tools[0].name == "fn"


def test_unknown_tool():
    registry = ToolRegistry()
    with pytest.raises(ToolError, match="Unknown tool"):
        registry.execute("missing", {})


def test_tool_failure():
    registry = ToolRegistry()
    registry.register("fail", lambda: 1 / 0, "fails", {"type": "object"})
    with pytest.raises(ToolError, match="failed"):
        registry.execute("fail", {})
