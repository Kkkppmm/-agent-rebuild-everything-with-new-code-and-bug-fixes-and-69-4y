"""Tests for developer tools."""

import tempfile
from pathlib import Path

from devai.tools.code_utils import (
    count_complexity,
    explain_code,
    lint_python,
    read_file,
    search_code,
)
from devai.tools.registry import ToolRegistry


SAMPLE_CODE = '''\
def hello(name):
  """Greet someone."""
  if name:
    return f"Hello, {name}!"
  return "Hello!"


def bad():
  try:
    pass
  except:
    print("error")
'''


def test_explain_code_python():
    result = explain_code(SAMPLE_CODE)
    assert "hello" in result
    assert "Functions:" in result


def test_explain_code_syntax_error():
    result = explain_code("def broken(")
    assert "Syntax error" in result


def test_lint_python_clean():
    clean = "def foo():\n    return 1\n"
    assert lint_python(clean) == "No issues found"


def test_lint_python_issues():
    result = lint_python(SAMPLE_CODE)
    assert "Bare except" in result or "print()" in result


def test_count_complexity():
    result = count_complexity(SAMPLE_CODE)
    assert "hello" in result
    assert "complexity=" in result


def test_read_file(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("print('hello')")
    result = read_file(str(f))
    assert "print('hello')" in result


def test_read_file_not_found():
    result = read_file("/nonexistent/file.py")
    assert "not found" in result.lower()


def test_search_code(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("def authenticate():\n    pass\n")
    result = search_code(str(tmp_path), "authenticate")
    assert "authenticate" in result


def test_tool_registry_builtins():
    registry = ToolRegistry()
    registry.register_builtins()
    assert len(registry) == 6
    assert "read_file" in registry


def test_tool_registry_execute():
    registry = ToolRegistry()
    registry.register_builtins()
    result = registry.execute("explain_code", {"code": "x = 1"})
    assert "Lines:" in result


def test_tool_registry_custom():
    registry = ToolRegistry()
    registry.register("double", lambda x: str(x * 2), "Double a number", {
        "type": "object",
        "properties": {"x": {"type": "integer"}},
        "required": ["x"],
    })
    assert registry.execute("double", {"x": 5}) == "10"


def test_tool_registry_unknown():
    registry = ToolRegistry()
    import pytest
    from devai.core.exceptions import ToolExecutionError
    with pytest.raises(ToolExecutionError):
        registry.execute("nonexistent", {})


def test_tool_definitions():
    registry = ToolRegistry()
    registry.register_builtins()
    defs = registry.get_definitions()
    assert all(d.name for d in defs)
