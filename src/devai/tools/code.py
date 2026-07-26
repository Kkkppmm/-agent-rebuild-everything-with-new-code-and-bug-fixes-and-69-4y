"""Tool registry and code utilities for agent tool-calling."""

from __future__ import annotations

import ast
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from devai.core.exceptions import ToolExecutionError
from devai.core.models import Tool


class ToolRegistry:
    """Registry for callable tools that agents can invoke."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        func: Callable[..., Any],
        description: str,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        self._tools[name] = func
        self._schemas[name] = Tool(
            name=name,
            description=description,
            parameters=parameters or {"type": "object", "properties": {}},
        )

    def get_tool(self, name: str) -> Tool:
        if name not in self._schemas:
            raise KeyError(f"Tool '{name}' not registered")
        return self._schemas[name]

    def list_tools(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolExecutionError(f"Tool '{name}' not found")
        try:
            result = self._tools[name](**arguments)
            return str(result) if not isinstance(result, str) else result
        except Exception as exc:
            raise ToolExecutionError(f"Tool '{name}' failed: {exc}") from exc


def explain_code(code: str, language: str = "python") -> str:
    """Provide a structural summary of code."""
    if language == "python":
        try:
            tree = ast.parse(code)
            functions = [
                node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            ]
            classes = [
                node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
            ]
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module or "")
            lines = len(code.splitlines())
            return (
                f"Lines: {lines}, Functions: {functions or 'none'}, "
                f"Classes: {classes or 'none'}, Imports: {imports or 'none'}"
            )
        except SyntaxError as exc:
            return f"Syntax error: {exc}"
    return f"Code has {len(code.splitlines())} lines ({language})"


def lint_python(code: str) -> str:
    """Run basic Python lint checks using AST analysis."""
    issues: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error on line {exc.lineno}: {exc.msg}"

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            if not ast.get_docstring(node) and len(node.body) > 3:
                issues.append(f"Function '{node.name}' missing docstring")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Bare except on line {node.lineno}")
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if re.match(r"^[a-z]+$", node.id) and len(node.id) == 1:
                issues.append(f"Single-letter variable '{node.id}' on line {node.lineno}")

    return "\n".join(issues) if issues else "No issues found"


def search_code(code: str, pattern: str) -> str:
    """Search for a regex pattern in code."""
    matches = []
    for i, line in enumerate(code.splitlines(), 1):
        if re.search(pattern, line):
            matches.append(f"Line {i}: {line.strip()}")
    return "\n".join(matches) if matches else "No matches found"


def git_diff(staged: bool = False) -> str:
    """Get git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout or "No changes"
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"Error: {exc}"


def read_file(path: str, max_lines: int = 200) -> str:
    """Read a file with line limit."""
    try:
        content = Path(path).read_text()
        lines = content.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines)"
        return content
    except OSError as exc:
        return f"Error reading file: {exc}"


def count_complexity(code: str) -> str:
    """Estimate cyclomatic complexity of Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

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

    if not complexities:
        return "No functions found"
    return json.dumps(complexities, indent=2)


def create_default_registry() -> ToolRegistry:
    """Create a registry with built-in developer tools."""
    registry = ToolRegistry()
    registry.register(
        "explain_code",
        explain_code,
        "Analyze and summarize code structure",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to analyze"},
                "language": {"type": "string", "description": "Programming language"},
            },
            "required": ["code"],
        },
    )
    registry.register(
        "lint_python",
        lint_python,
        "Run basic Python lint checks",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python source code"},
            },
            "required": ["code"],
        },
    )
    registry.register(
        "search_code",
        search_code,
        "Search for a regex pattern in code",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "pattern": {"type": "string"},
            },
            "required": ["code", "pattern"],
        },
    )
    registry.register(
        "git_diff",
        git_diff,
        "Get git diff of current changes",
        {
            "type": "object",
            "properties": {
                "staged": {"type": "boolean", "description": "Show staged changes only"},
            },
        },
    )
    registry.register(
        "read_file",
        read_file,
        "Read contents of a file",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "max_lines": {"type": "integer", "description": "Max lines to read"},
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
            "properties": {
                "code": {"type": "string", "description": "Python source code"},
            },
            "required": ["code"],
        },
    )
    return registry
