"""Tests for DevAI tools."""

import os
import tempfile

import pytest

from devai.tools import (
    ToolRegistry,
    explain_code,
    lint_python,
    search_code,
    read_file,
    count_complexity,
    list_files,
)
from devai.core.exceptions import ToolExecutionError


class TestToolRegistry:
    def test_register_and_execute(self):
        registry = ToolRegistry()

        def greet(name: str) -> str:
            """Greet someone."""
            return f"Hello, {name}!"

        registry.register(greet)
        assert len(registry) == 1
        result = registry.execute("greet", {"name": "World"})
        assert result == "Hello, World!"

    def test_unknown_tool(self):
        registry = ToolRegistry()
        with pytest.raises(ToolExecutionError):
            registry.execute("missing", {})

    def test_list_tools(self):
        registry = ToolRegistry()
        registry.register(explain_code)
        tools = registry.list_tools()
        assert len(tools) == 1
        assert tools[0].name == "explain_code"


class TestExplainCode:
    def test_python_functions(self):
        code = "def foo(x):\n    return x\n\ndef bar(y):\n    pass"
        result = explain_code(code)
        assert "foo" in result
        assert "bar" in result

    def test_syntax_error(self):
        result = explain_code("def broken(:")
        assert "syntax" in result.lower()


class TestLintPython:
    def test_clean_code(self):
        result = lint_python("def foo():\n    return 1")
        assert "No issues" in result

    def test_long_line(self):
        result = lint_python("x = " + "a" * 200)
        assert "120 characters" in result

    def test_syntax_error(self):
        result = lint_python("def broken(:")
        assert "Syntax error" in result


class TestSearchCode:
    def test_search_in_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "test.py"), "w") as f:
                f.write("def hello_world():\n    pass\n")
            result = search_code(tmpdir, "hello_world")
            assert "hello_world" in result

    def test_no_matches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = search_code(tmpdir, "nonexistent_pattern_xyz")
            assert "No matches" in result


class TestReadFile:
    def test_read_existing(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello')")
            path = f.name
        result = read_file(path)
        assert "hello" in result
        os.unlink(path)

    def test_missing_file(self):
        result = read_file("/nonexistent/path/file.py")
        assert "not found" in result.lower()


class TestCountComplexity:
    def test_simple_function(self):
        code = "def simple():\n    return 1"
        result = count_complexity(code)
        assert "simple" in result
        assert "complexity=1" in result

    def test_branching(self):
        code = "def branch(x):\n    if x > 0:\n        return 1\n    else:\n        return 0"
        result = count_complexity(code)
        assert "complexity=2" in result


class TestListFiles:
    def test_list_python_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "main.py"), "w") as f:
                f.write("print('hi')")
            os.makedirs(os.path.join(tmpdir, "pkg"), exist_ok=True)
            with open(os.path.join(tmpdir, "pkg", "util.py"), "w") as f:
                f.write("x = 1")
            result = list_files(tmpdir, "*.py")
            assert "main.py" in result
            assert "pkg/util.py" in result

    def test_missing_directory(self):
        result = list_files("/nonexistent/path")
        assert "not found" in result.lower()
