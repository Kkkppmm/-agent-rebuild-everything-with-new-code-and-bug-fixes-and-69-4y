"""Built-in developer tools for agents."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from typing import Any

from devai.tools.registry import ToolRegistry


def create_dev_tools(root: str | Path = ".") -> ToolRegistry:
  """Create a ToolRegistry pre-loaded with developer utilities."""
  registry = ToolRegistry()
  base = Path(root).resolve()

  @registry.register(description="Read the contents of a file relative to the project root.")
  def read_file(path: str) -> str:
    target = _safe_path(base, path)
    if not target.is_file():
      return f"Error: file not found: {path}"
    return target.read_text(encoding="utf-8", errors="replace")

  @registry.register(description="List files in a directory relative to the project root.")
  def list_directory(path: str = ".") -> list[str]:
    target = _safe_path(base, path)
    if not target.is_dir():
      return [f"Error: directory not found: {path}"]
    return sorted(p.name for p in target.iterdir())

  @registry.register(description="Search for a regex pattern in code files.")
  def search_code(pattern: str, file_glob: str = "*.py") -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    regex = re.compile(pattern)
    for file_path in base.rglob(file_glob):
      if not file_path.is_file():
        continue
      try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
      except OSError:
        continue
      for i, line in enumerate(text.splitlines(), 1):
        if regex.search(line):
          results.append({
            "file": str(file_path.relative_to(base)),
            "line": i,
            "content": line.strip(),
          })
    return results[:50]

  @registry.register(description="Get git diff for the current repository.")
  def git_diff(staged: bool = False) -> str:
    cmd = ["git", "diff"]
    if staged:
      cmd.append("--staged")
    try:
      result = subprocess.run(
        cmd,
        cwd=base,
        capture_output=True,
        text=True,
        timeout=30,
      )
      return result.stdout or result.stderr or "(no diff)"
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
      return f"Error running git diff: {exc}"

  @registry.register(description="Explain what a Python code snippet does (static analysis).")
  def explain_code(code: str) -> dict[str, Any]:
    try:
      tree = ast.parse(code)
    except SyntaxError as exc:
      return {"error": f"Syntax error: {exc}"}

    functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    imports = []
    for node in ast.walk(tree):
      if isinstance(node, ast.Import):
        imports.extend(alias.name for alias in node.names)
      elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        imports.extend(f"{module}.{alias.name}" if module else alias.name for alias in node.names)

    return {
      "functions": functions,
      "classes": classes,
      "imports": imports,
      "lines": len(code.splitlines()),
    }

  @registry.register(description="Lint Python code for common issues (basic static checks).")
  def lint_python(code: str) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    try:
      tree = ast.parse(code)
    except SyntaxError as exc:
      return [{"line": str(exc.lineno or 0), "issue": f"Syntax error: {exc.msg}"}]

    for node in ast.walk(tree):
      if isinstance(node, ast.FunctionDef) and not node.body:
        issues.append({"line": str(node.lineno), "issue": f"Empty function: {node.name}"})
      if isinstance(node, ast.ExceptHandler) and node.type is None:
        issues.append({"line": str(node.lineno), "issue": "Bare except clause"})
    return issues

  @registry.register(description="Calculate cyclomatic complexity of Python functions.")
  def count_complexity(code: str) -> list[dict[str, Any]]:
    try:
      tree = ast.parse(code)
    except SyntaxError as exc:
      return [{"error": str(exc)}]

    results: list[dict[str, Any]] = []
    for node in ast.walk(tree):
      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        complexity = _cyclomatic_complexity(node)
        results.append({"name": node.name, "complexity": complexity, "line": node.lineno})
    return results

  return registry


def _safe_path(base: Path, path: str) -> Path:
  target = (base / path).resolve()
  if not str(target).startswith(str(base)):
    raise ValueError(f"Path escapes project root: {path}")
  return target


def _cyclomatic_complexity(node: ast.AST) -> int:
  complexity = 1
  branch_nodes = (
    ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
    ast.With, ast.AsyncWith, ast.Assert, ast.comprehension,
  )
  for child in ast.walk(node):
    if isinstance(child, branch_nodes):
      complexity += 1
    elif isinstance(child, ast.BoolOp):
      complexity += len(child.values) - 1
  return complexity
