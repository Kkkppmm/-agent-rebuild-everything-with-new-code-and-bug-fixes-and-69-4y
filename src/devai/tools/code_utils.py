"""Built-in developer tools."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any


def explain_code(code: str, language: str = "python") -> str:
    """Provide a structural explanation of code."""
    if language == "python":
        try:
            tree = ast.parse(code)
            functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            imports = []
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    imports.extend(a.name for a in n.names)
                elif isinstance(n, ast.ImportFrom):
                    imports.append(n.module or "")
            lines = len(code.splitlines())
            return (
                f"Language: Python\n"
                f"Lines: {lines}\n"
                f"Functions: {', '.join(functions) or 'none'}\n"
                f"Classes: {', '.join(classes) or 'none'}\n"
                f"Imports: {', '.join(imports) or 'none'}"
            )
        except SyntaxError as exc:
            return f"Syntax error in code: {exc}"
    return f"Language: {language}, Lines: {len(code.splitlines())}"


def lint_python(code: str) -> str:
    """Basic Python lint checks without external dependencies."""
    issues: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"SyntaxError: {exc}"

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            if not ast.get_docstring(node) and len(node.body) > 3:
                issues.append(f"Line {node.lineno}: Function '{node.name}' missing docstring")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Line {node.lineno}: Bare except clause")

    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(f"Line {i}: Line too long ({len(line)} chars)")
        if re.search(r"\bprint\(", line) and not line.strip().startswith("#"):
            issues.append(f"Line {i}: print() statement found")

    return "\n".join(issues) if issues else "No issues found"


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    """Search for a regex pattern in files."""
    root = Path(directory)
    if not root.exists():
        return f"Directory not found: {directory}"

    results: list[str] = []
    regex = re.compile(pattern)
    for path in root.rglob(file_glob):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                results.append(f"{path}:{i}: {line.strip()}")

    return "\n".join(results[:50]) if results else "No matches found"


def git_diff(staged: bool = False) -> str:
    """Get git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout or "No changes"
    except (subprocess.SubprocessError, FileNotFoundError):
        return "Git not available or command failed"


def read_file(path: str, max_lines: int = 500) -> str:
    """Read a file with line limit."""
    file_path = Path(path)
    if not file_path.exists():
        return f"File not found: {path}"
    if not file_path.is_file():
        return f"Not a file: {path}"

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"Error reading file: {exc}"

    if len(lines) > max_lines:
        truncated = lines[:max_lines]
        truncated.append(f"... ({len(lines) - max_lines} more lines)")
        return "\n".join(truncated)
    return "\n".join(lines)


def count_complexity(code: str) -> str:
    """Calculate cyclomatic complexity for Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"SyntaxError: {exc}"

    def _complexity(node: ast.AST) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
        return complexity

    results: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            c = _complexity(node)
            level = "low" if c <= 5 else "medium" if c <= 10 else "high"
            results.append(f"{node.name}: complexity={c} ({level})")

    return "\n".join(results) if results else "No functions found"


BUILTIN_TOOLS: dict[str, dict[str, Any]] = {
    "explain_code": {
        "fn": explain_code,
        "description": "Analyze and explain code structure",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to analyze"},
                "language": {"type": "string", "description": "Programming language", "default": "python"},
            },
            "required": ["code"],
        },
    },
    "lint_python": {
        "fn": lint_python,
        "description": "Run basic lint checks on Python code",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python source code"},
            },
            "required": ["code"],
        },
    },
    "search_code": {
        "fn": search_code,
        "description": "Search for a regex pattern in source files",
        "parameters": {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Directory to search"},
                "pattern": {"type": "string", "description": "Regex pattern"},
                "file_glob": {"type": "string", "description": "File glob pattern", "default": "*.py"},
            },
            "required": ["directory", "pattern"],
        },
    },
    "git_diff": {
        "fn": git_diff,
        "description": "Get the current git diff",
        "parameters": {
            "type": "object",
            "properties": {
                "staged": {"type": "boolean", "description": "Show staged changes only", "default": False},
            },
        },
    },
    "read_file": {
        "fn": read_file,
        "description": "Read contents of a file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
                "max_lines": {"type": "integer", "description": "Maximum lines to read", "default": 500},
            },
            "required": ["path"],
        },
    },
    "count_complexity": {
        "fn": count_complexity,
        "description": "Calculate cyclomatic complexity of Python functions",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python source code"},
            },
            "required": ["code"],
        },
    },
}
