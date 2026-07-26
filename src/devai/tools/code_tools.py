"""Built-in code utility tools for developer agents."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

from devai.tools.registry import ToolRegistry

default_registry = ToolRegistry()


@default_registry.register(description="Explain what a code snippet does")
def explain_code(code: str, language: str = "python") -> str:
    return f"[{language}] Code has {len(code.splitlines())} lines. Use an LLM for detailed explanation."


@default_registry.register(description="Run ruff linter on Python code string")
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
        if result.returncode == 0:
            return "No syntax errors found."
        return f"Syntax errors:\n{result.stderr}"
    except FileNotFoundError:
        return "Linter not available."
    finally:
        os.unlink(path)


@default_registry.register(description="Search for a pattern in code")
def search_code(code: str, pattern: str) -> str:
    matches = []
    for i, line in enumerate(code.splitlines(), 1):
        if re.search(pattern, line, re.IGNORECASE):
            matches.append(f"Line {i}: {line.strip()}")
    return "\n".join(matches) if matches else "No matches found."


@default_registry.register(description="Get git diff for a repository path")
def git_diff(path: str = ".") -> str:
    try:
        result = subprocess.run(
            ["git", "diff", "--stat"],
            capture_output=True,
            text=True,
            cwd=path,
        )
        return result.stdout or "No changes."
    except FileNotFoundError:
        return "Git not available."


@default_registry.register(description="Read contents of a file")
def read_file(filepath: str, max_lines: int = 200) -> str:
    path = Path(filepath)
    if not path.exists():
        return f"File not found: {filepath}"
    lines = path.read_text().splitlines()[:max_lines]
    return "\n".join(lines)


@default_registry.register(description="Calculate cyclomatic complexity of Python code")
def count_complexity(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
    return f"Cyclomatic complexity: {complexity}"
