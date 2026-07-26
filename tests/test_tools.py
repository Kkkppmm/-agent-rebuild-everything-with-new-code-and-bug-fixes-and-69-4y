"""Tests for tool registry and utilities."""

import tempfile
from pathlib import Path

import pytest

from devai.core.exceptions import ToolError
from devai.tools import (
    ToolRegistry,
    count_complexity,
    explain_code,
    list_directory,
    read_file,
    search_code,
    write_file,
)


class TestToolRegistry:
    def test_register_and_execute(self):
        registry = ToolRegistry()

        def greet(name: str) -> str:
            """Greet someone."""
            return f"Hello, {name}!"

        registry.register(greet)
        assert len(registry.get_tool_definitions()) == 1
        result = registry.execute("greet", '{"name": "Dev"}')
        assert result == "Hello, Dev!"

    def test_unknown_tool(self):
        registry = ToolRegistry()
        with pytest.raises(ToolError):
            registry.execute("missing", "{}")

    def test_schema_generation(self):
        registry = ToolRegistry()

        def add(a: int, b: int) -> int:
            return a + b

        registry.register(add)
        tools = registry.get_tool_definitions()
        assert tools[0].name == "add"
        assert "a" in tools[0].parameters["properties"]


class TestCodeUtilities:
    def test_read_write_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            write_file(path, "test content")
            assert read_file(path) == "test content"
        finally:
            Path(path).unlink()

    def test_explain_code(self):
        code = "def foo():\n    return 42\n\nclass Bar:\n    pass"
        result = explain_code(code)
        assert "foo" in result
        assert "Bar" in result

    def test_count_complexity(self):
        code = """
def simple():
    return 1

def complex(x):
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                pass
"""
        result = count_complexity(code)
        assert "simple" in result
        assert "complex" in result

    def test_search_code(self, tmp_path):
        (tmp_path / "test.py").write_text("def hello():\n    print('hi')\n")
        result = search_code(str(tmp_path), "hello")
        assert "hello" in result

    def test_list_directory(self, tmp_path):
        (tmp_path / "file.txt").write_text("x")
        (tmp_path / "subdir").mkdir()
        result = list_directory(str(tmp_path))
        assert "file.txt" in result
        assert "subdir" in result
