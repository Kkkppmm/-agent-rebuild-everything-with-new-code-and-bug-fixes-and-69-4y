"""Tests for tools module."""


import pytest

from devai.core.exceptions import ToolExecutionError
from devai.tools import (
  ToolRegistry,
  count_complexity,
  explain_code,
  lint_python,
  list_files,
  read_file,
  search_code,
)


def test_read_file(tmp_path):
  f = tmp_path / "test.txt"
  f.write_text("hello\nworld")
  assert read_file(str(f)) == "hello\nworld"


def test_read_file_not_found():
  with pytest.raises(ToolExecutionError):
    read_file("/nonexistent/file.txt")


def test_list_files(tmp_path):
  (tmp_path / "a.py").write_text("x")
  (tmp_path / "b.py").write_text("y")
  (tmp_path / "sub").mkdir()
  (tmp_path / "sub" / "c.py").write_text("z")
  files = list_files(str(tmp_path), "*.py")
  assert len(files) == 3


def test_search_code(tmp_path):
  (tmp_path / "main.py").write_text("def hello():\n    pass\n# TODO: fix\n")
  results = search_code(str(tmp_path), "TODO")
  assert len(results) == 1
  assert results[0]["line"] == 3


def test_lint_python_valid(tmp_path):
  f = tmp_path / "good.py"
  f.write_text("def add(a, b):\n    '''Add numbers.'''\n    return a + b\n")
  result = lint_python(str(f))
  assert result["valid"] is True


def test_lint_python_syntax_error(tmp_path):
  f = tmp_path / "bad.py"
  f.write_text("def broken(:\n")
  result = lint_python(str(f))
  assert result["valid"] is False


def test_count_complexity(tmp_path):
  f = tmp_path / "complex.py"
  f.write_text("def simple():\n    return 1\n\ndef branch(x):\n    if x:\n        return 1\n    return 0\n")
  result = count_complexity(str(f))
  assert len(result["functions"]) == 2
  assert result["functions"][1]["complexity"] >= 2


def test_explain_code(tmp_path):
  f = tmp_path / "module.py"
  f.write_text("class Foo:\n    def bar(self): pass\n\ndef baz(): pass\n")
  summary = explain_code(str(f))
  assert "Foo" in summary
  assert "baz" in summary


def test_tool_registry_register_and_execute():
  registry = ToolRegistry()
  registry.register("double", "Double a number", lambda x: x * 2, {
    "type": "object",
    "properties": {"x": {"type": "integer"}},
    "required": ["x"],
  })
  assert registry.execute("double", {"x": 5}) == "10"


def test_tool_registry_default():
  registry = ToolRegistry.default()
  defs = registry.get_definitions()
  names = {d.name for d in defs}
  assert "read_file" in names
  assert "search_code" in names
  assert "lint_python" in names


def test_tool_registry_unknown_tool():
  registry = ToolRegistry()
  with pytest.raises(ToolExecutionError):
    registry.execute("nonexistent", {})
