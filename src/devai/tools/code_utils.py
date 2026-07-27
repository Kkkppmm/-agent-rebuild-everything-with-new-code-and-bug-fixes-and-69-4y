"""Developer tool registry and utilities."""

from __future__ import annotations

import ast
import inspect
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from devai.core.models import ToolDefinition


class ToolRegistry:
  """Registry for agent-callable tools."""

  def __init__(self) -> None:
    self._tools: dict[str, Callable[..., Any]] = {}
    self._definitions: dict[str, ToolDefinition] = {}

  def register(self, fn: Callable[..., Any], *, description: str | None = None) -> None:
    name = fn.__name__
    self._tools[name] = fn
    doc = description or (fn.__doc__ or f"Tool: {name}").strip().split("\n")[0]
    sig = inspect.signature(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param_name, param in sig.parameters.items():
      if param_name == "self":
        continue
      prop_type = "string"
      if param.annotation in (int, float):
        prop_type = "number"
      elif param.annotation is bool:
        prop_type = "boolean"
      properties[param_name] = {"type": prop_type, "description": param_name}
      if param.default is inspect.Parameter.empty:
        required.append(param_name)
    self._definitions[name] = ToolDefinition(
      name=name,
      description=doc,
      parameters={
        "type": "object",
        "properties": properties,
        "required": required,
      },
    )

  def get_definitions(self) -> list[ToolDefinition]:
    return list(self._definitions.values())

  def execute(self, name: str, arguments: dict[str, Any]) -> str:
    if name not in self._tools:
      return f"Error: unknown tool '{name}'"
    try:
      result = self._tools[name](**arguments)
      return str(result)
    except (TypeError, ValueError, OSError, KeyError) as exc:
      return f"Error executing {name}: {exc}"

  def __len__(self) -> int:
    return len(self._tools)


def read_file(path: str, max_lines: int = 200) -> str:
  """Read contents of a file, truncated to max_lines."""
  p = Path(path)
  if not p.exists():
    return f"File not found: {path}"
  lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
  if len(lines) > max_lines:
    content = "\n".join(lines[:max_lines])
    return f"{content}\n... (truncated, {len(lines)} total lines)"
  return "\n".join(lines)


def list_files(directory: str = ".", pattern: str = "*") -> str:
  """List files in a directory matching a glob pattern."""
  root = Path(directory)
  if not root.is_dir():
    return f"Not a directory: {directory}"
  files = sorted(
    str(p.relative_to(root)) for p in root.rglob(pattern) if p.is_file()
  )[:100]
  return "\n".join(files) if files else "No files found"


def search_code(query: str, directory: str = ".", file_pattern: str = "*.py") -> str:
  """Search for a regex pattern in source files."""
  root = Path(directory)
  matches: list[str] = []
  try:
    compiled = re.compile(query)
  except re.error as exc:
    return f"Invalid regex: {exc}"
  for path in root.rglob(file_pattern):
    if not path.is_file():
      continue
    try:
      for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if compiled.search(line):
          matches.append(f"{path}:{i}: {line.strip()}")
          if len(matches) >= 50:
            return "\n".join(matches) + "\n... (truncated)"
    except OSError:
      continue
  return "\n".join(matches) if matches else "No matches found"


def git_diff(staged: bool = False) -> str:
  """Get git diff output."""
  cmd = ["git", "diff"]
  if staged:
    cmd.append("--staged")
  try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    return result.stdout or "No changes"
  except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
    return f"Error: {exc}"


def explain_code(code: str, language: str = "python") -> str:
  """Provide a structural explanation of code without an LLM."""
  if language == "python":
    try:
      tree = ast.parse(code)
      functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
      classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
      imports = [
        n.names[0].name
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        and hasattr(n, "names")
      ]
      parts = []
      if imports:
        parts.append(f"Imports: {', '.join(imports[:10])}")
      if classes:
        parts.append(f"Classes: {', '.join(classes)}")
      if functions:
        parts.append(f"Functions: {', '.join(functions)}")
      return "\n".join(parts) if parts else "Empty or unparseable code"
    except SyntaxError as exc:
      return f"Syntax error: {exc}"
  return f"Code analysis for {language} not supported locally"


def lint_python(code: str) -> str:
  """Basic Python lint checks using AST."""
  issues: list[str] = []
  try:
    tree = ast.parse(code)
  except SyntaxError as exc:
    return f"Syntax error on line {exc.lineno}: {exc.msg}"

  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
      if not node.body:
        issues.append(f"Empty function: {node.name}")
      if not ast.get_docstring(node) and not node.name.startswith("_"):
        issues.append(f"Missing docstring: {node.name} (line {node.lineno})")
    if isinstance(node, ast.ExceptHandler) and node.type is None:
      issues.append(f"Bare except on line {node.lineno}")
  return "\n".join(issues) if issues else "No issues found"


def count_complexity(code: str) -> str:
  """Estimate cyclomatic complexity of Python functions."""
  try:
    tree = ast.parse(code)
  except SyntaxError as exc:
    return f"Syntax error: {exc}"

  results: list[str] = []
  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
      complexity = 1
      for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
          complexity += 1
        elif isinstance(child, ast.BoolOp):
          complexity += len(child.values) - 1
      results.append(f"{node.name}: complexity {complexity}")
  return "\n".join(results) if results else "No functions found"


def default_registry() -> ToolRegistry:
  """Create a registry with all built-in tools."""
  registry = ToolRegistry()
  for tool in [read_file, list_files, search_code, git_diff, explain_code, lint_python, count_complexity]:
    registry.register(tool)
  return registry
