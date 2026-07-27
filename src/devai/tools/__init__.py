"""Built-in tools for agents and assistants."""

from __future__ import annotations

import ast
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from devai.core.exceptions import ToolExecutionError
from devai.core.models import ToolDefinition


def read_file(path: str, max_lines: int = 500) -> str:
  """Read a file and return its contents."""
  try:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
      content = "\n".join(lines[:max_lines])
      return f"{content}\n... [{len(lines) - max_lines} more lines truncated]"
    return "\n".join(lines)
  except OSError as e:
    raise ToolExecutionError(f"Cannot read {path}: {e}") from e


def list_files(directory: str, pattern: str = "*", recursive: bool = True) -> list[str]:
  """List files in a directory matching a glob pattern."""
  root = Path(directory)
  if not root.is_dir():
    raise ToolExecutionError(f"Not a directory: {directory}")
  globber = root.rglob(pattern) if recursive else root.glob(pattern)
  return sorted(str(p) for p in globber if p.is_file())


def search_code(directory: str, query: str, file_pattern: str = "*.py") -> list[dict[str, Any]]:
  """Search for a regex pattern in code files."""
  results = []
  try:
    compiled = re.compile(query)
  except re.error as e:
    raise ToolExecutionError(f"Invalid regex: {e}") from e
  for path in list_files(directory, file_pattern):
    try:
      text = Path(path).read_text(encoding="utf-8", errors="replace")
      for i, line in enumerate(text.splitlines(), 1):
        if compiled.search(line):
          results.append({"file": path, "line": i, "content": line.strip()})
    except OSError:
      continue
  return results[:100]


def git_diff(path: str = ".", staged: bool = False) -> str:
  """Get git diff for a path."""
  cmd = ["git", "diff"]
  if staged:
    cmd.append("--staged")
  cmd.append("--")
  cmd.append(path)
  try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    return result.stdout or "(no changes)"
  except (subprocess.TimeoutExpired, FileNotFoundError) as e:
    raise ToolExecutionError(f"git diff failed: {e}") from e


def lint_python(path: str) -> dict[str, Any]:
  """Basic Python linting using AST analysis."""
  try:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=path)
  except (OSError, SyntaxError) as e:
    return {"file": path, "valid": False, "error": str(e), "issues": []}

  issues = []
  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and not node.name.startswith("_") and not ast.get_docstring(node) and len(node.body) > 3:
      issues.append({"line": node.lineno, "type": "missing_docstring", "name": node.name})
    if isinstance(node, ast.ExceptHandler) and node.type is None:
      issues.append({"line": node.lineno, "type": "bare_except"})
  return {"file": path, "valid": True, "issues": issues}


def count_complexity(path: str) -> dict[str, Any]:
  """Count cyclomatic complexity per function."""
  try:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=path)
  except (OSError, SyntaxError) as e:
    return {"file": path, "error": str(e)}

  functions = []
  for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
      complexity = 1
      for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
          complexity += 1
        elif isinstance(child, ast.BoolOp):
          complexity += len(child.values) - 1
      functions.append({"name": node.name, "line": node.lineno, "complexity": complexity})
  return {"file": path, "functions": functions}


def explain_code(path: str) -> str:
  """Return code with basic structure summary."""
  try:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=path)
  except (OSError, SyntaxError) as e:
    return f"Error parsing {path}: {e}"

  parts = [f"File: {path}", f"Lines: {len(source.splitlines())}"]
  for node in ast.iter_child_nodes(tree):
    if isinstance(node, ast.ClassDef):
      methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
      parts.append(f"Class {node.name} (line {node.lineno}): methods={methods}")
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
      parts.append(f"Function {node.name} (line {node.lineno})")
  return "\n".join(parts)


class ToolRegistry:
  """Registry of callable tools for agents."""

  def __init__(self) -> None:
    self._tools: dict[str, tuple[ToolDefinition, Callable[..., Any]]] = {}

  def register(self, name: str, description: str, fn: Callable[..., Any], parameters: dict | None = None) -> None:
    params = parameters or self._infer_parameters(fn)
    definition = ToolDefinition(name=name, description=description, parameters=params)
    self._tools[name] = (definition, fn)

  def get_definitions(self) -> list[ToolDefinition]:
    return [d for d, _ in self._tools.values()]

  def execute(self, name: str, arguments: dict[str, Any]) -> str:
    if name not in self._tools:
      raise ToolExecutionError(f"Unknown tool: {name}")
    _, fn = self._tools[name]
    try:
      result = fn(**arguments)
      return result if isinstance(result, str) else json.dumps(result, indent=2, default=str)
    except TypeError as e:
      raise ToolExecutionError(f"Tool {name} argument error: {e}") from e
    except Exception as e:
      raise ToolExecutionError(f"Tool {name} failed: {e}") from e

  @classmethod
  def default(cls) -> ToolRegistry:
    registry = cls()
    registry.register("read_file", "Read contents of a file", read_file, {
      "type": "object",
      "properties": {"path": {"type": "string"}, "max_lines": {"type": "integer"}},
      "required": ["path"],
    })
    registry.register("list_files", "List files in a directory", list_files, {
      "type": "object",
      "properties": {
        "directory": {"type": "string"},
        "pattern": {"type": "string"},
        "recursive": {"type": "boolean"},
      },
      "required": ["directory"],
    })
    registry.register("search_code", "Search code with regex", search_code, {
      "type": "object",
      "properties": {
        "directory": {"type": "string"},
        "query": {"type": "string"},
        "file_pattern": {"type": "string"},
      },
      "required": ["directory", "query"],
    })
    registry.register("git_diff", "Get git diff", git_diff, {
      "type": "object",
      "properties": {"path": {"type": "string"}, "staged": {"type": "boolean"}},
    })
    registry.register("lint_python", "Lint a Python file", lint_python, {
      "type": "object",
      "properties": {"path": {"type": "string"}},
      "required": ["path"],
    })
    registry.register("count_complexity", "Measure cyclomatic complexity", count_complexity, {
      "type": "object",
      "properties": {"path": {"type": "string"}},
      "required": ["path"],
    })
    registry.register("explain_code", "Summarize code structure", explain_code, {
      "type": "object",
      "properties": {"path": {"type": "string"}},
      "required": ["path"],
    })
    return registry

  @staticmethod
  def _infer_parameters(fn: Callable[..., Any]) -> dict[str, Any]:
    import inspect
    sig = inspect.signature(fn)
    props: dict[str, Any] = {}
    required = []
    for name, param in sig.parameters.items():
      if name in ("self", "cls"):
        continue
      props[name] = {"type": "string"}
      if param.default is inspect.Parameter.empty:
        required.append(name)
    return {"type": "object", "properties": props, "required": required}
