"""Code utility tools for developer agents."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any


def read_file(path: str, max_lines: int = 500) -> str:
    """Read a file and return its contents (truncated to max_lines)."""
    p = Path(path)
    if not p.exists():
        return f"Error: File not found: {path}"
    if not p.is_file():
        return f"Error: Not a file: {path}"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        content = "\n".join(lines[:max_lines])
        return f"{content}\n\n... (truncated, {len(lines) - max_lines} more lines)"
    return "\n".join(lines)


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    """Search for a regex pattern in files under a directory."""
    results: list[str] = []
    root = Path(directory)
    if not root.exists():
        return f"Error: Directory not found: {directory}"
    try:
        regex = re.compile(pattern)
    except re.error as e:
        return f"Error: Invalid regex: {e}"
    for path in root.rglob(file_glob):
        if path.is_file():
            try:
                for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if regex.search(line):
                        results.append(f"{path}:{i}: {line.strip()}")
                        if len(results) >= 50:
                            return "\n".join(results) + "\n... (truncated at 50 matches)"
            except (OSError, UnicodeDecodeError):
                continue
    return "\n".join(results) if results else "No matches found."


def git_diff(path: str = ".", staged: bool = False) -> str:
    """Get git diff for a path."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    cmd.extend(["--", path])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=path if path != "." else None)
        if result.returncode != 0 and not result.stdout:
            return f"Error: {result.stderr.strip()}"
        return result.stdout or "No changes."
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"Error: {e}"


def lint_python(path: str) -> str:
    """Run basic Python linting checks (syntax + common issues)."""
    p = Path(path)
    if not p.exists():
        return f"Error: File not found: {path}"
    source = p.read_text(encoding="utf-8", errors="replace")
    issues: list[str] = []
    try:
        tree = ast.parse(source, filename=str(p))
    except SyntaxError as e:
        return f"Syntax error at line {e.lineno}: {e.msg}"
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.body:
            issues.append(f"Line {node.lineno}: Empty function '{node.name}'")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Line {node.lineno}: Bare except clause")
        if isinstance(node, ast.Import) and any(alias.name == "*" for alias in node.names):
            issues.append(f"Line {node.lineno}: Wildcard import")
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(f"Line {i}: Line too long ({len(line)} chars)")
        if line.rstrip() != line and line.strip():
            issues.append(f"Line {i}: Trailing whitespace")
    return "\n".join(issues) if issues else "No issues found."


def count_complexity(path: str) -> dict[str, Any]:
    """Calculate cyclomatic complexity for Python functions."""
    p = Path(path)
    if not p.exists():
        return {"error": f"File not found: {path}"}
    source = p.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(p))
    except SyntaxError as e:
        return {"error": f"Syntax error: {e.msg}"}
    functions: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = _cyclomatic_complexity(node)
            functions.append({
                "name": node.name,
                "line": node.lineno,
                "complexity": complexity,
            })
    return {
        "file": str(p),
        "functions": functions,
        "max_complexity": max((f["complexity"] for f in functions), default=0),
        "avg_complexity": round(
            sum(f["complexity"] for f in functions) / len(functions), 2
        ) if functions else 0,
    }


def explain_code(path: str) -> str:
    """Return a structural summary of Python code (AST-based)."""
    p = Path(path)
    if not p.exists():
        return f"Error: File not found: {path}"
    source = p.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(p))
    except SyntaxError as e:
        return f"Syntax error: {e.msg}"
    classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    top_level_funcs = [
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.extend(f"{module}.{alias.name}" for alias in node.names)
    lines = [
        f"File: {p}",
        f"Lines: {len(source.splitlines())}",
        f"Classes: {', '.join(classes) or 'none'}",
        f"Top-level functions: {', '.join(top_level_funcs) or 'none'}",
        f"Imports: {', '.join(imports[:10]) or 'none'}",
    ]
    return "\n".join(lines)


def _cyclomatic_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    complexity = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
        elif isinstance(child, (ast.And, ast.Or)):
            complexity += 1
    return complexity


def create_default_registry() -> "ToolRegistry":
    """Create a ToolRegistry with all built-in code tools."""
    from devai.tools.registry import ToolRegistry

    registry = ToolRegistry()
    registry.register(read_file)
    registry.register(search_code)
    registry.register(git_diff)
    registry.register(lint_python)
    registry.register(count_complexity)
    registry.register(explain_code)
    return registry
