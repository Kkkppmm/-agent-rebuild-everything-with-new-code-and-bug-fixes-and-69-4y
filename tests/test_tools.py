"""Tests for tools module."""

import pytest

from devai.core.exceptions import ToolError
from devai.tools.registry import ToolRegistry
from devai.tools.code_utils import create_code_tools


class TestToolRegistry:
    def test_register_and_execute(self):
        registry = ToolRegistry()

        @registry.register(description="Add two numbers")
        def add(a: int, b: int) -> int:
            return a + b

        assert "add" in registry
        assert registry.execute("add", {"a": 2, "b": 3}) == "5"

    def test_unknown_tool_raises(self):
        registry = ToolRegistry()
        with pytest.raises(ToolError):
            registry.execute("nonexistent", {})

    def test_get_definitions(self):
        registry = ToolRegistry()

        @registry.register()
        def greet(name: str) -> str:
            """Say hello."""
            return f"Hello {name}"

        defs = registry.get_definitions()
        assert len(defs) == 1
        assert defs[0].name == "greet"


class TestCodeTools:
  def test_explain_code(self):
      tools = create_code_tools()
      result = tools.execute("explain_code", {"code": "def foo():\n    pass\nclass Bar:\n    pass"})
      assert "foo" in result
      assert "Bar" in result

  def test_lint_python_clean(self):
      tools = create_code_tools()
      result = tools.execute("lint_python", {"code": "x = 1\n"})
      assert "No issues" in result

  def test_lint_python_syntax_error(self):
      tools = create_code_tools()
      result = tools.execute("lint_python", {"code": "def ("})
      assert "Syntax error" in result

  def test_search_code(self):
      tools = create_code_tools()
      result = tools.execute("search_code", {"code": "foo\nbar\nfoo", "pattern": "foo"})
      assert "Line 1" in result
      assert "Line 3" in result

  def test_count_complexity(self):
      tools = create_code_tools()
      code = "def simple():\n    return 1\n\ndef complex(x):\n    if x > 0:\n        for i in range(x):\n            if i % 2:\n                pass\n    return x"
      result = tools.execute("count_complexity", {"code": code})
      assert "simple" in result
      assert "complex" in result

  def test_read_file_not_found(self):
      tools = create_code_tools()
      result = tools.execute("read_file", {"filepath": "/nonexistent/file.py"})
      assert "not found" in result.lower()
