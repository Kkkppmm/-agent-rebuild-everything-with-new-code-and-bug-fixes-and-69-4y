"""Tests for developer tools."""

from devai.tools import (
  ToolRegistry,
  count_complexity,
  explain_code,
  lint_python,
  list_files,
  read_file,
  search_code,
)


def test_tool_registry():
  registry = ToolRegistry()

  def greet(name: str) -> str:
    """Say hello."""
    return f"Hello {name}"

  registry.register(greet)
  assert len(registry) == 1
  assert registry.execute("greet", {"name": "World"}) == "Hello World"


def test_read_file(tmp_path):
  f = tmp_path / "test.py"
  f.write_text("print('hello')")
  result = read_file(str(f))
  assert "print" in result


def test_list_files(tmp_path):
  (tmp_path / "a.py").write_text("")
  (tmp_path / "b.py").write_text("")
  result = list_files(str(tmp_path), "*.py")
  assert "a.py" in result
  assert "b.py" in result


def test_search_code(tmp_path):
  f = tmp_path / "main.py"
  f.write_text("def hello():\n    pass\n# TODO: fix\n")
  result = search_code("TODO", str(tmp_path))
  assert "TODO" in result


def test_explain_code():
  code = "def add(a, b):\n    return a + b\n"
  result = explain_code(code)
  assert "add" in result


def test_lint_python_clean():
  code = 'def foo():\n    """Doc."""\n    return 1\n'
  assert "No issues" in lint_python(code)


def test_lint_python_bare_except():
  code = "try:\n    pass\nexcept:\n    pass\n"
  result = lint_python(code)
  assert "Bare except" in result


def test_count_complexity():
  code = "def simple():\n    return 1\n\ndef complex(x):\n    if x > 0:\n        for i in range(x):\n            if i % 2:\n                pass\n"
  result = count_complexity(code)
  assert "simple" in result
  assert "complex" in result
