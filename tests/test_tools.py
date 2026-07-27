"""Tests for developer tools."""


from devai.tools import (
    ToolRegistry,
    count_complexity,
    explain_code,
    lint_python,
    list_directory,
    read_file,
    search_code,
)


def test_read_file(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("print('hello')")
    assert "hello" in read_file(str(f))


def test_read_file_missing():
    assert "not found" in read_file("/nonexistent/file.py")


def test_search_code(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("def authenticate():\n    pass\n")
    result = search_code(str(tmp_path), "authenticate")
    assert "authenticate" in result


def test_lint_python(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text("def foo():\n    try:\n        pass\n    except:\n        pass\n")
    result = lint_python(str(f))
    assert "bare except" in result


def test_count_complexity(tmp_path):
    f = tmp_path / "complex.py"
    f.write_text("def simple():\n    return 1\n\ndef complex_fn(x):\n    if x:\n        for i in range(x):\n            if i % 2:\n                pass\n")
    result = count_complexity(str(f))
    assert "simple" in result
    assert "complex_fn" in result


def test_explain_code(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text("import os\n\ndef main():\n    pass\n")
    result = explain_code(str(f))
    assert "main" in result


def test_list_directory(tmp_path):
    (tmp_path / "a.py").write_text("")
    result = list_directory(str(tmp_path))
    assert "a.py" in result


def test_tool_registry():
    registry = ToolRegistry()
    registry.register(read_file)
    defs = registry.get_definitions()
    assert len(defs) == 1
    assert defs[0].name == "read_file"


def test_tool_registry_execute(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("content")
    registry = ToolRegistry()
    registry.register(read_file)
    result = registry.execute("read_file", {"path": str(f)})
    assert result == "content"
