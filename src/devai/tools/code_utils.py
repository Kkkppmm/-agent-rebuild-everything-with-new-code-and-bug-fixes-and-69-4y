"""Code utility tools for agents."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any


def explain_code(code: str, language: str = "python") -> str:
    """Provide a structural summary of code."""
    if language == "python":
        try:
            tree = ast.parse(code)
            functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            imports = [
                alias.name
                for n in ast.walk(tree)
                if isinstance(n, ast.Import)
                for alias in n.names
            ]
            return (
                f"Functions: {', '.join(functions) or 'none'}\n"
                f"Classes: {', '.join(classes) or 'none'}\n"
                f"Imports: {', '.join(imports) or 'none'}\n"
                f"Lines: {len(code.splitlines())}"
            )
        except SyntaxError as e:
            return f"Syntax error: {e}"
    return f"Code has {len(code.splitlines())} lines ({language})"


def lint_python(code: str) -> list[str]:
    """Basic Python lint checks without external dependencies."""
    issues: list[str] = []
    try:
        ast.parse(code)
    except SyntaxError as e:
        issues.append(f"Syntax error line {e.lineno}: {e.msg}")
        return issues

    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(f"Line {i}: exceeds 120 characters")
        if "\t" in line:
            issues.append(f"Line {i}: contains tabs (use spaces)")
        if line.rstrip() != line:
            issues.append(f"Line {i}: trailing whitespace")

    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Line {node.lineno}: bare except clause")
        if isinstance(node, ast.FunctionDef) and not node.body:
            issues.append(f"Line {node.lineno}: empty function '{node.name}'")

    return issues


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> list[dict[str, Any]]:
    """Search for a regex pattern in source files."""
    results: list[dict[str, Any]] = []
    root = Path(directory)
    if not root.is_dir():
        return results
    regex = re.compile(pattern)
    for path in root.rglob(file_glob):
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(text.splitlines(), 1):
                    if regex.search(line):
                        results.append({"file": str(path), "line": i, "content": line.strip()})
            except OSError:
                continue
    return results


def git_diff(cwd: str | None = None) -> str:
    """Return the current git diff."""
    try:
        result = subprocess.run(
            ["git", "diff"],
            capture_output=True,
            text=True,
            cwd=cwd or ".",
            timeout=10,
        )
        return result.stdout or "(no changes)"
    except (subprocess.SubprocessError, FileNotFoundError):
        return "(git not available)"


def read_file(path: str, max_lines: int = 500) -> str:
    """Read a file, truncating if too long."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines)"
        return "\n".join(lines)
    except OSError as e:
        return f"Error reading file: {e}"


def count_complexity(code: str) -> dict[str, int]:
    """Count cyclomatic complexity for Python functions."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"error": 1}

    complexities: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            complexities[node.name] = complexity
    return complexities
