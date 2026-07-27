"""Developer tool registry and built-in tools."""

from __future__ import annotations

import ast
import inspect
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from devai.core.exceptions import ToolError
from devai.core.models import ToolDefinition


class ToolRegistry:
    """Registry for callable tools used by agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._definitions: dict[str, ToolDefinition] = {}

    def register(self, fn: Callable[..., Any], *, name: str | None = None, description: str | None = None) -> None:
        tool_name = name or fn.__name__
        doc = description or (fn.__doc__ or f"Execute {tool_name}").strip().split("\n")[0]
        sig = inspect.signature(fn)
        properties: dict[str, Any] = {}
        required: list[str] = []
        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            prop: dict[str, Any] = {"type": "string"}
            if param.annotation is int:
                prop["type"] = "integer"
            elif param.annotation is bool:
                prop["type"] = "boolean"
            properties[param_name] = prop
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        definition = ToolDefinition(
            name=tool_name,
            description=doc,
            parameters={
                "type": "object",
                "properties": properties,
                "required": required,
            },
        )
        self._tools[tool_name] = fn
        self._definitions[tool_name] = definition

    def get_definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        try:
            result = self._tools[name](**arguments)
            return str(result) if result is not None else ""
        except Exception as exc:
            raise ToolError(f"Tool {name} failed: {exc}") from exc


def read_file(path: str) -> str:
    """Read the contents of a file."""
    if not path:
        return "Error: path is required"
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    if p.is_dir():
        return f"Error: path is a directory: {path}"
    return p.read_text(encoding="utf-8", errors="replace")


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    """Search for a regex pattern in source files."""
    results: list[str] = []
    root = Path(directory)
    if not root.exists():
        return f"Error: directory not found: {directory}"
    for fp in root.rglob(file_glob):
        if fp.is_file():
            try:
                for i, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if re.search(pattern, line):
                        results.append(f"{fp}:{i}: {line.strip()}")
            except OSError:
                continue
    return "\n".join(results[:50]) if results else "No matches found."


def git_diff(staged: bool = False) -> str:
    """Get git diff of changes."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout or "No changes."
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"Error running git diff: {exc}"


def lint_python(path: str) -> str:
    """Run basic Python lint checks using AST parsing."""
    try:
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"
    except OSError as exc:
        return f"Error reading file: {exc}"

    issues: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            if not ast.get_docstring(node) and len(node.body) > 3:
                issues.append(f"Line {node.lineno}: function '{node.name}' lacks docstring")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Line {node.lineno}: bare except clause")
    return "\n".join(issues) if issues else "No issues found."


def count_complexity(path: str) -> str:
    """Estimate cyclomatic complexity of Python functions."""
    try:
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path)
    except (SyntaxError, OSError) as exc:
        return f"Error: {exc}"

    results: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            results.append(f"{node.name} (line {node.lineno}): complexity {complexity}")
    return "\n".join(results) if results else "No functions found."


def explain_code(path: str) -> str:
    """Provide a structural summary of a Python file."""
    try:
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path)
    except (SyntaxError, OSError) as exc:
        return f"Error: {exc}"

    parts: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            parts.append(f"imports: {', '.join(a.name for a in node.names)}")
        elif isinstance(node, ast.ImportFrom):
            parts.append(f"from {node.module} import ...")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in node.args.args]
            parts.append(f"function {node.name}({', '.join(args)}) at line {node.lineno}")
        elif isinstance(node, ast.ClassDef):
            parts.append(f"class {node.name} at line {node.lineno}")
    return "\n".join(parts) if parts else "Empty module."


def list_directory(path: str = ".") -> str:
    """List files in a directory."""
    p = Path(path)
    if not p.is_dir():
        return f"Error: not a directory: {path}"
    entries = sorted(os.listdir(p))
    return "\n".join(entries[:100])
