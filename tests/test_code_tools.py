"""Tests for developer code tools."""

import tempfile
from pathlib import Path

from devai.tools.code_tools import create_dev_tools


def test_read_file():
  with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "hello.py"
    path.write_text("print('hello')")
    tools = create_dev_tools(tmp)
    result = tools.execute("read_file", {"path": "hello.py"})
    assert "print('hello')" in result


def test_list_directory():
  with tempfile.TemporaryDirectory() as tmp:
    (Path(tmp) / "a.py").touch()
    (Path(tmp) / "b.py").touch()
    tools = create_dev_tools(tmp)
    result = tools.execute("list_directory", {"path": "."})
    data = __import__("json").loads(result)
    assert "a.py" in data
    assert "b.py" in data


def test_explain_code():
  tools = create_dev_tools()
  code = "def foo():\n    return 42\n\nclass Bar:\n    pass"
  result = tools.execute("explain_code", {"code": code})
  data = __import__("json").loads(result)
  assert "foo" in data["functions"]
  assert "Bar" in data["classes"]


def test_lint_python():
  tools = create_dev_tools()
  code = "def empty():\n    pass\n\ntry:\n    x = 1\nexcept:\n    pass"
  result = tools.execute("lint_python", {"code": code})
  data = __import__("json").loads(result)
  assert any("Bare except" in i["issue"] for i in data)


def test_count_complexity():
  tools = create_dev_tools()
  code = "def simple():\n    return 1\n\ndef complex(x):\n    if x > 0:\n        for i in range(x):\n            if i % 2 == 0:\n                pass\n    return x"
  result = tools.execute("count_complexity", {"code": code})
  data = __import__("json").loads(result)
  names = {item["name"]: item["complexity"] for item in data}
  assert names["simple"] == 1
  assert names["complex"] > 1
