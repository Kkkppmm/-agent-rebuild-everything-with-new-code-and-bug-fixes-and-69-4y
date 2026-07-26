"""Tests for developer tools."""

import pytest

from devai.tools import (
    DEFAULT_REGISTRY,
    ToolRegistry,
    count_complexity,
    explain_code,
    function_to_tool,
    lint_python,
    search_code,
)


def test_explain_code():
    result = explain_code("a = 1\nb = 2", "python")
    assert "2 non-empty lines" in result


def test_lint_python_valid():
    assert "No syntax errors" in lint_python("def foo(): pass")


def test_lint_python_invalid():
    result = lint_python("def foo(")
    assert "Syntax error" in result


def test_search_code():
    result = search_code("hello world\nfoo bar", r"foo")
    assert "Found 1" in result


def test_search_code_no_match():
    assert "No matches" in search_code("abc", r"xyz")


def test_count_complexity():
    code = "def f():\n    if True:\n        for i in range(3):\n            pass"
    result = count_complexity(code)
    assert "complexity" in result


def test_function_to_tool():
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    tool = function_to_tool(add)
    assert tool.name == "add"
    assert "a" in tool.parameters["properties"]
    assert "a" in tool.parameters["required"]


def test_tool_registry_register_and_execute():
    registry = ToolRegistry()

    @registry.register
    def greet(name: str) -> str:
        """Greet someone."""
        return f"Hello {name}"

    assert len(registry.schemas()) == 1
    assert registry.execute("greet", {"name": "Dev"}) == "Hello Dev"


def test_tool_registry_unknown_tool():
    registry = ToolRegistry()
    with pytest.raises(KeyError):
        registry.execute("missing", {})


def test_default_registry_has_tools():
    schemas = DEFAULT_REGISTRY.schemas()
    names = {s.name for s in schemas}
    assert "lint_python" in names
    assert "explain_code" in names
