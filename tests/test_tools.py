"""Tests for DevAI tools."""

import tempfile
from pathlib import Path

import pytest

from devai.tools.registry import ToolRegistry
from devai.tools.code_utils import (
    read_file,
    search_code,
    lint_python,
    count_complexity,
    explain_code,
    create_default_registry,
)
from devai.core.exceptions import ToolExecutionError


class TestToolRegistry:
    def test_register_decorator(self):
        registry = ToolRegistry()

        @registry.register(description="Add two numbers")
        def add(a: int, b: int) -> int:
            return a + b

        assert "add" in registry
        assert len(registry) == 1
        tools = registry.get_tools()
        assert tools[0].name == "add"

    def test_execute_sync(self):
        registry = ToolRegistry()

        @registry.register()
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        result = registry.execute_sync("greet", {"name": "World"})
        assert result == "Hello, World!"

    @pytest.mark.asyncio
    async def test_execute_async(self):
        registry = ToolRegistry()

        @registry.register()
        async def async_add(a: int, b: int) -> int:
            return a + b

        result = await registry.execute("async_add", {"a": 2, "b": 3})
        assert result == "5"

    def test_unknown_tool_raises(self):
        registry = ToolRegistry()
        with pytest.raises(ToolExecutionError):
            registry.execute_sync("nonexistent", {})

    def test_infer_schema(self):
        registry = ToolRegistry()

        @registry.register()
        def search(query: str, limit: int = 10) -> str:
            return query

        tools = registry.get_tools()
        params = tools[0].parameters
        assert "query" in params["properties"]
        assert "query" in params["required"]
        assert "limit" not in params["required"]


class TestCodeUtils:
    def test_read_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')\n")
        result = read_file(str(f))
        assert "print('hello')" in result

    def test_read_file_not_found(self):
        result = read_file("/nonexistent/file.py")
        assert "Error" in result

    def test_search_code(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text("def hello():\n    return 'world'\n")
        result = search_code(str(tmp_path), "hello")
        assert "hello" in result

    def test_lint_python_clean(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("def add(a, b):\n    return a + b\n")
        result = lint_python(str(f))
        assert "No issues" in result

    def test_lint_python_issues(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text("try:\n    pass\nexcept:\n    pass\n")
        result = lint_python(str(f))
        assert "Bare except" in result

    def test_count_complexity(self, tmp_path):
        f = tmp_path / "complex.py"
        f.write_text(
            "def simple():\n    return 1\n\n"
            "def complex_fn(x):\n    if x > 0:\n        if x > 10:\n            return x\n    return 0\n"
        )
        result = count_complexity(str(f))
        assert result["max_complexity"] >= 3
        assert len(result["functions"]) == 2

    def test_explain_code(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("import os\n\nclass App:\n    pass\n\ndef main():\n    pass\n")
        result = explain_code(str(f))
        assert "App" in result
        assert "main" in result

    def test_create_default_registry(self):
        registry = create_default_registry()
        assert len(registry) == 6
        assert "read_file" in registry
