"""Code and developer utility tools for agents."""

from __future__ import annotations

import ast
import inspect
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from devai.core.models import Tool


def _python_type(annotation: Any) -> str:
    if annotation is inspect.Parameter.empty:
        return "string"
    if annotation in (int, float):
        return "number"
    if annotation is bool:
        return "boolean"
    if annotation is list:
        return "array"
    return "string"


def function_to_tool(fn: Callable[..., Any]) -> Tool:
    """Convert a Python function into a DevAI Tool schema."""
    sig = inspect.signature(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        properties[name] = {
            "type": _python_type(param.annotation),
            "description": f"Parameter {name}",
        }
        if param.default is inspect.Parameter.empty:
            required.append(name)
    return Tool(
        name=fn.__name__,
        description=(fn.__doc__ or f"Tool: {fn.__name__}").strip(),
        parameters={
            "type": "object",
            "properties": properties,
            "required": required,
        },
    )


class ToolRegistry:
    """Registry mapping tool names to callable functions."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        tool = function_to_tool(fn)
        self._tools[tool.name] = fn
        self._schemas[tool.name] = tool
        return fn

    def get_schema(self, name: str) -> Tool:
        return self._schemas[name]

    def schemas(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        result = self._tools[name](**arguments)
        return str(result) if result is not None else ""


def explain_code(code: str, language: str = "python") -> str:
    """Summarize what the given code does."""
    lines = [line.strip() for line in code.strip().splitlines() if line.strip()]
    return f"{language} snippet with {len(lines)} non-empty lines."


def lint_python(code: str) -> str:
    """Run basic Python syntax checks."""
    try:
        ast.parse(code)
        return "No syntax errors found."
    except SyntaxError as exc:
        return f"Syntax error at line {exc.lineno}: {exc.msg}"


def search_code(code: str, pattern: str) -> str:
    """Search for a regex pattern in code."""
    matches = re.findall(pattern, code, re.MULTILINE)
    if not matches:
        return "No matches found."
    return f"Found {len(matches)} match(es): {matches[:10]}"


def read_file(path: str) -> str:
    """Read a file from disk."""
    return Path(path).read_text(encoding="utf-8")


def git_diff(staged: bool = False) -> str:
    """Return git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--cached")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout or result.stderr or "(empty diff)"


def count_complexity(code: str) -> str:
    """Estimate cyclomatic complexity for Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Cannot analyze: {exc.msg}"

    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
    return f"Estimated cyclomatic complexity: {complexity}"


DEFAULT_REGISTRY = ToolRegistry()
DEFAULT_REGISTRY.register(explain_code)
DEFAULT_REGISTRY.register(lint_python)
DEFAULT_REGISTRY.register(search_code)
DEFAULT_REGISTRY.register(read_file)
DEFAULT_REGISTRY.register(git_diff)
DEFAULT_REGISTRY.register(count_complexity)
