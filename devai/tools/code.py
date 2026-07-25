"""Developer-focused built-in tools."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any


def explain_code(code: str, language: str = "python") -> str:
  """Summarize what a code snippet does (structural analysis, no LLM required)."""
  if language.lower() == "python":
    try:
      tree = ast.parse(code)
    except SyntaxError as exc:
      return f"Syntax error: {exc}"
    functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    imports = []
    for node in ast.walk(tree):
      if isinstance(node, ast.Import):
        imports.extend(alias.name for alias in node.names)
      elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        imports.extend(f"{module}.{alias.name}" if module else alias.name for alias in node.names)
    lines = [f"Language: {language}", f"Lines: {len(code.splitlines())}"]
    if functions:
      lines.append(f"Functions: {', '.join(functions)}")
    if classes:
      lines.append(f"Classes: {', '.join(classes)}")
    if imports:
      lines.append(f"Imports: {', '.join(imports[:10])}")
    return "\n".join(lines)
  return f"Language: {language}\nLines: {len(code.splitlines())}"


def lint_python(code: str) -> list[dict[str, Any]]:
  """Run basic static checks on Python code."""
  issues: list[dict[str, Any]] = []
  try:
    tree = ast.parse(code)
  except SyntaxError as exc:
    return [{"line": exc.lineno, "message": str(exc), "severity": "error"}]

  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and not node.body:
      issues.append(
        {
          "line": node.lineno,
          "message": f"Empty function '{node.name}'",
          "severity": "warning",
        }
      )
    if isinstance(node, ast.ExceptHandler) and node.type is None:
      issues.append(
        {
          "line": node.lineno,
          "message": "Bare except clause",
          "severity": "warning",
        }
      )
  return issues


def extract_functions(code: str) -> list[dict[str, Any]]:
  """Extract function signatures from Python source."""
  try:
    tree = ast.parse(code)
  except SyntaxError:
    return []
  result = []
  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
      args = [arg.arg for arg in node.args.args]
      result.append(
        {
          "name": node.name,
          "args": args,
          "line": node.lineno,
          "docstring": ast.get_docstring(node),
        }
      )
  return result


def read_file(path: str, *, max_bytes: int = 100_000) -> str:
  """Read a file from disk (for agent tool use)."""
  file_path = Path(path).expanduser().resolve()
  if not file_path.is_file():
    raise FileNotFoundError(f"File not found: {path}")
  content = file_path.read_bytes()[:max_bytes]
  return content.decode("utf-8", errors="replace")


def search_code(directory: str, pattern: str, *, glob: str = "*.py") -> list[dict[str, Any]]:
  """Search for a regex pattern in source files."""
  root = Path(directory).expanduser().resolve()
  if not root.is_dir():
    raise NotADirectoryError(f"Not a directory: {directory}")
  compiled = re.compile(pattern)
  matches: list[dict[str, Any]] = []
  for file_path in root.rglob(glob):
    if not file_path.is_file():
      continue
    try:
      text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
      continue
    for line_no, line in enumerate(text.splitlines(), start=1):
      if compiled.search(line):
        matches.append({"file": str(file_path), "line": line_no, "text": line.strip()})
        if len(matches) >= 100:
          return matches
  return matches


def format_json(data: str | dict[str, Any], *, indent: int = 2) -> str:
  """Pretty-print JSON data."""
  if isinstance(data, str):
    parsed = json.loads(data)
  else:
    parsed = data
  return json.dumps(parsed, indent=indent, default=str)
