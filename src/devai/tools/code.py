"""Code utility tools for DevAI agents."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path


def explain_code(code: str, language: str = "python") -> str:
    """Return a brief structural summary of code."""
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
                f"Python code: {len(functions)} functions ({', '.join(functions) or 'none'}), "
                f"{len(classes)} classes ({', '.join(classes) or 'none'}), "
                f"imports: {', '.join(imports) or 'none'}"
            )
        except SyntaxError as exc:
            return f"Syntax error: {exc}"
    lines = [ln for ln in code.strip().splitlines() if ln.strip()]
    return f"{language} code: {len(lines)} lines"


def lint_python(code: str) -> str:
    """Run basic Python lint checks using AST."""
    issues: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error on line {exc.lineno}: {exc.msg}"

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            if not ast.get_docstring(node) and len(node.body) > 3:
                issues.append(f"Function '{node.name}' lacks docstring (line {node.lineno})")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Bare except clause on line {node.lineno}")

    long_lines = [i + 1 for i, ln in enumerate(code.splitlines()) if len(ln) > 100]
    for ln in long_lines[:5]:
        issues.append(f"Line {ln} exceeds 100 characters")

    return "\n".join(issues) if issues else "No issues found."


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    """Search for a regex pattern in files under a directory."""
    root = Path(directory)
    if not root.is_dir():
        return f"Directory not found: {directory}"

    regex = re.compile(pattern)
    matches: list[str] = []
    for path in root.rglob(file_glob):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                matches.append(f"{path}:{i}: {line.strip()[:120]}")
                if len(matches) >= 50:
                    return "\n".join(matches) + "\n... (truncated)"

    return "\n".join(matches) if matches else "No matches found."


def git_diff(staged: bool = False) -> str:
    """Return git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout or "No changes."
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"Git diff failed: {exc}"


def read_file(path: str, max_lines: int = 200) -> str:
    """Read a file with line limit."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            return f"{content}\n... ({len(lines) - max_lines} more lines)"
        return "\n".join(lines)
    except OSError as exc:
        return f"Cannot read file: {exc}"


def count_complexity(code: str) -> str:
    """Estimate cyclomatic complexity for Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

    complexities: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            complexities.append(f"{node.name}: {complexity}")

    if not complexities:
        return "No functions found."
    return "\n".join(complexities)


def register_code_tools(registry: "ToolRegistry") -> None:
    """Register all code utility tools."""
    from devai.tools.registry import ToolRegistry

    registry.register(
        "explain_code",
        explain_code,
        "Analyze code structure and return a summary",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to analyze"},
                "language": {"type": "string", "description": "Programming language", "default": "python"},
            },
            "required": ["code"],
        },
    )
    registry.register(
        "lint_python",
        lint_python,
        "Run basic Python lint checks on code",
        {
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Python source code"}},
            "required": ["code"],
        },
    )
    registry.register(
        "search_code",
        search_code,
        "Search for a regex pattern in files",
        {
            "type": "object",
            "properties": {
                "directory": {"type": "string"},
                "pattern": {"type": "string"},
                "file_glob": {"type": "string", "default": "*.py"},
            },
            "required": ["directory", "pattern"],
        },
    )
    registry.register(
        "git_diff",
        git_diff,
        "Get git diff of current changes",
        {
            "type": "object",
            "properties": {"staged": {"type": "boolean", "default": False}},
        },
    )
    registry.register(
        "read_file",
        read_file,
        "Read contents of a file",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "max_lines": {"type": "integer", "default": 200},
            },
            "required": ["path"],
        },
    )
    registry.register(
        "count_complexity",
        count_complexity,
        "Calculate cyclomatic complexity of Python functions",
        {
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
        },
    )
