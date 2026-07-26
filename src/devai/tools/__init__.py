"""Tool registry and developer utility tools."""

from __future__ import annotations

import ast
import inspect
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, get_type_hints

from devai.core.exceptions import ToolError
from devai.core.models import Tool


class ToolRegistry:
    """Registry for LLM-callable tools."""

    def __init__(self):
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(self, func: Callable[..., Any], *, description: str | None = None) -> None:
        """Register a function as a tool."""
        name = func.__name__
        self._tools[name] = func
        self._schemas[name] = self._build_schema(func, description)

    def get_tool_definitions(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: str | dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        try:
            result = self._tools[name](**arguments)
            return str(result) if not isinstance(result, str) else result
        except Exception as exc:
            raise ToolError(f"Tool '{name}' failed: {exc}") from exc

    def _build_schema(self, func: Callable[..., Any], description: str | None) -> Tool:
        sig = inspect.signature(func)
        hints = get_type_hints(func) if hasattr(func, "__annotations__") else {}
        properties: dict[str, Any] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            prop_type = self._python_type_to_json(hints.get(param_name, str))
            properties[param_name] = {"type": prop_type, "description": f"Parameter {param_name}"}
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        doc = description or (func.__doc__ or f"Execute {func.__name__}").strip().split("\n")[0]

        return Tool(
            name=func.__name__,
            description=doc,
            parameters={
                "type": "object",
                "properties": properties,
                "required": required,
            },
        )

    @staticmethod
    def _python_type_to_json(py_type: type) -> str:
        mapping = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}
        return mapping.get(py_type, "string")


def read_file(path: str) -> str:
    """Read the contents of a file."""
    return Path(path).read_text(encoding="utf-8")


def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    Path(path).write_text(content, encoding="utf-8")
    return f"Written {len(content)} bytes to {path}"


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    """Search for a regex pattern in files within a directory."""
    results: list[str] = []
    regex = re.compile(pattern)
    for path in Path(directory).rglob(file_glob):
        if path.is_file():
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if regex.search(line):
                    results.append(f"{path}:{i}: {line.strip()}")
    return "\n".join(results) if results else "No matches found."


def explain_code(code: str) -> str:
    """Return basic AST analysis of Python code."""
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
        return (
            f"Functions: {', '.join(functions) or 'none'}\n"
            f"Classes: {', '.join(classes) or 'none'}\n"
            f"Imports: {', '.join(imports) or 'none'}\n"
            f"Lines: {len(code.splitlines())}"
        )
    except SyntaxError as exc:
        return f"Syntax error: {exc}"


def lint_python(path: str) -> str:
    """Run ruff linter on a Python file."""
    try:
        result = subprocess.run(
            ["ruff", "check", path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout or result.stderr or "No issues found."
    except FileNotFoundError:
        return "ruff not installed. Install with: pip install ruff"
    except subprocess.TimeoutExpired:
        return "Linting timed out."


def git_diff(staged: bool = False) -> str:
    """Get git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout or "No changes."
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "Git not available or timed out."


def count_complexity(code: str) -> str:
    """Calculate cyclomatic complexity of Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

    complexities: dict[str, int] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            complexities[node.name] = complexity

    if not complexities:
        return "No functions found."
    lines = [f"{name}: complexity {score}" for name, score in sorted(complexities.items())]
    return "\n".join(lines)


def list_directory(path: str = ".") -> str:
    """List files in a directory."""
    p = Path(path)
    if not p.is_dir():
        return f"Not a directory: {path}"
    entries = sorted(p.iterdir())
    return "\n".join(
        f"{'[dir]' if e.is_dir() else '[file]'} {e.name}" for e in entries
    )
