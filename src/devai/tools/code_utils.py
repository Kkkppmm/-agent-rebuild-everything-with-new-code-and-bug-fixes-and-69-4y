"""Code utility tools for agents."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from devai.tools.registry import ToolRegistry


def create_code_tools() -> ToolRegistry:
    """Create a registry with built-in developer tools."""
    registry = ToolRegistry()

    @registry.register(description="Explain what a Python code snippet does")
    def explain_code(code: str) -> str:
        try:
            tree = ast.parse(code)
            functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            imports = [
                n.names[0].name
                for n in ast.walk(tree)
                if isinstance(n, (ast.Import, ast.ImportFrom))
            ]
            return (
                f"Functions: {functions or 'none'}\n"
                f"Classes: {classes or 'none'}\n"
                f"Imports: {imports or 'none'}\n"
                f"Lines: {len(code.splitlines())}"
            )
        except SyntaxError as exc:
            return f"Syntax error: {exc}"

    @registry.register(description="Lint Python code for basic issues")
    def lint_python(code: str) -> str:
        issues: list[str] = []
        try:
            ast.parse(code)
        except SyntaxError as exc:
            return f"Syntax error on line {exc.lineno}: {exc.msg}"

        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            if len(line) > 120:
                issues.append(f"Line {i}: exceeds 120 characters")
            if re.search(r"\bprint\(", line) and "debug" not in line.lower():
                issues.append(f"Line {i}: print statement found")
            if re.search(r"except\s*:", line):
                issues.append(f"Line {i}: bare except clause")

        return "\n".join(issues) if issues else "No issues found."

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
                cwd=path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout or result.stderr or "No changes."
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return f"Error: {exc}"

    @registry.register(description="Read contents of a file")
    def read_file(filepath: str, max_lines: int = 200) -> str:
        path = Path(filepath)
        if not path.exists():
            return f"File not found: {filepath}"
        if not path.is_file():
            return f"Not a file: {filepath}"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
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

        complexities: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                complexity = 1
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                        complexity += 1
                    elif isinstance(child, ast.BoolOp):
                        complexity += len(child.values) - 1
                complexities[node.name] = complexity

        if not complexities:
            return "No functions found."
        lines = [f"{name}: complexity {score}" for name, score in complexities.items()]
        avg = sum(complexities.values()) / len(complexities)
        lines.append(f"Average complexity: {avg:.1f}")
        return "\n".join(lines)

    return registry
