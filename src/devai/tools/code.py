"""Code utility tools for developers."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

from devai.tools.registry import ToolRegistry

registry = ToolRegistry()


@registry.register(description="Explain what a Python code snippet does at a high level")
def explain_code(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"
    functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    imports = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            imports.extend(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.module:
            imports.append(n.module)
    lines = len(code.splitlines())
    parts = [f"Lines: {lines}"]
    if functions:
        parts.append(f"Functions: {', '.join(functions)}")
    if classes:
        parts.append(f"Classes: {', '.join(classes)}")
    if imports:
        parts.append(f"Imports: {', '.join(imports[:10])}")
    return "; ".join(parts)


@registry.register(description="Run ruff linter on Python code and return issues")
def lint_python(code: str) -> str:
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        result = subprocess.run(
            ["python3", "-m", "py_compile", path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return f"Syntax errors:\n{result.stderr}"
        return "No syntax errors found."
    finally:
        os.unlink(path)


@registry.register(description="Search for a pattern in code")
def search_code(code: str, pattern: str) -> str:
    matches = []
    for i, line in enumerate(code.splitlines(), 1):
        if re.search(pattern, line, re.IGNORECASE):
            matches.append(f"Line {i}: {line.strip()}")
    return "\n".join(matches) if matches else "No matches found."


@registry.register(description="Get git diff for a repository path")
def git_diff(path: str = ".") -> str:
    try:
        result = subprocess.run(
            ["git", "diff", "--stat"],
            capture_output=True,
            text=True,
            cwd=path,
        )
        if result.stdout:
            return result.stdout
        result = subprocess.run(
            ["git", "diff", "--cached", "--stat"],
            capture_output=True,
            text=True,
            cwd=path,
        )
        return result.stdout or "No changes detected."
    except FileNotFoundError:
        return "git not available"


@registry.register(description="Read contents of a file")
def read_file(path: str, max_lines: int = 200) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return f"File not found: {path}"
    if not file_path.is_file():
        return f"Not a file: {path}"
    lines = file_path.read_text().splitlines()
    if len(lines) > max_lines:
        content = "\n".join(lines[:max_lines])
        return f"{content}\n... ({len(lines) - max_lines} more lines)"
    return "\n".join(lines)


@registry.register(description="Calculate cyclomatic complexity of Python code")
def count_complexity(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
    rating = "low" if complexity <= 5 else "medium" if complexity <= 10 else "high"
    return f"Cyclomatic complexity: {complexity} ({rating})"
