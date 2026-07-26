"""Tests for tool registry and code tools."""

import pytest

from devai.core.exceptions import ToolExecutionError
from devai.tools.registry import ToolRegistry
from devai.tools.code_tools import default_registry, search_code, count_complexity


class TestToolRegistry:
    def test_register_and_execute(self):
        registry = ToolRegistry()

        @registry.register(description="Add two numbers")
        def add(a: int, b: int) -> int:
            return a + b

        assert "add" in registry
        assert registry.execute("add", {"a": 2, "b": 3}) == "5"

    def test_list_tools(self):
        registry = ToolRegistry()

        @registry.register()
        def greet(name: str) -> str:
            """Say hello."""
            return f"Hello {name}"

        tools = registry.list_tools()
        assert len(tools) == 1
        assert tools[0].name == "greet"

    def test_unknown_tool_raises(self):
        registry = ToolRegistry()
        with pytest.raises(ToolExecutionError):
            registry.execute("nonexistent", {})

    def test_decorator_without_call(self):
        registry = ToolRegistry()

        @registry.register
        def double(x: int) -> int:
            return x * 2

        assert registry.execute("double", {"x": 5}) == "10"


class TestCodeTools:
    def test_search_code(self):
        code = "def foo():\n    return 42\n\ndef bar():\n    pass"
        result = search_code(code, "return")
        assert "Line 2" in result

    def test_count_complexity(self):
        code = "def f():\n    if True:\n        for i in range(10):\n            pass"
        result = count_complexity(code)
        assert "complexity: 3" in result

    def test_default_registry_has_tools(self):
        assert len(default_registry) >= 5
