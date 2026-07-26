"""Tool registry and code utilities for DevAI."""

import ast
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from devai.core.exceptions import ToolExecutionError
from devai.core.models import ToolDefinition


@dataclass
class Tool:
    """A registered tool with its handler and schema."""

    definition: ToolDefinition
    handler: Callable[..., Any]


class ToolRegistry:
    """Registry for tools available to agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, func: Callable[..., Any], **schema_kwargs: Any) -> Tool:
        name = schema_kwargs.get("name", func.__name__)
        description = schema_kwargs.get("description", func.__doc__ or f"Tool: {name}")
        parameters = schema_kwargs.get("parameters", _infer_parameters(func))
        definition = ToolDefinition(name=name, description=description, parameters=parameters)
        tool = Tool(definition=definition, handler=func)
        self._tools[name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolExecutionError(f"Unknown tool: {name}")
        try:
            return tool.handler(**arguments)
        except Exception as e:
            raise ToolExecutionError(f"Tool '{name}' failed: {e}") from e

    def list_tools(self) -> list[ToolDefinition]:
        return [t.definition for t in self._tools.values()]

    def schemas(self) -> list[dict[str, Any]]:
        return [t.definition.to_schema() for t in self._tools.values()]

    def __len__(self) -> int:
        return len(self._tools)


def _infer_parameters(func: Callable[..., Any]) -> dict[str, Any]:
    """Infer JSON schema parameters from function signature."""
    import inspect
    sig = inspect.signature(func)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        prop: dict[str, Any] = {"type": "string"}
        if param.default is not inspect.Parameter.empty:
            prop["default"] = param.default
        else:
            required.append(name)
        properties[name] = prop
    return {"type": "object", "properties": properties, "required": required}


def explain_code(code: str, language: str = "python") -> str:
    """Explain what a piece of code does."""
    lines = code.strip().split("\n")
    summary = f"Code snippet ({language}, {len(lines)} lines):\n"
    if language == "python":
        try:
            tree = ast.parse(code)
            functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            if functions:
                summary += f"Functions: {', '.join(functions)}\n"
            if classes:
                summary += f"Classes: {', '.join(classes)}\n"
        except SyntaxError:
            summary += "Note: code has syntax errors.\n"
    summary += f"\nFirst line: {lines[0][:80]}"
    return summary


def lint_python(code: str) -> str:
    """Basic Python linting checks."""
    issues: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"Syntax error: {e}"

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if not node.name.islower() and "_" not in node.name:
                issues.append(f"Function '{node.name}' should use snake_case")
            if len(node.body) > 50:
                issues.append(f"Function '{node.name}' is very long ({len(node.body)} statements)")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("_"):
                    issues.append(f"Importing private module: {alias.name}")

    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(f"Line {i}: exceeds 120 characters")
        if line.rstrip() != line:
            issues.append(f"Line {i}: trailing whitespace")

    if not issues:
        return "No issues found."
    return "Issues:\n" + "\n".join(f"- {issue}" for issue in issues)


def search_code(directory: str, pattern: str, file_extension: str = ".py") -> str:
    """Search for a regex pattern in source files."""
    results: list[str] = []
    path = Path(directory)
    if not path.exists():
        return f"Directory not found: {directory}"

    regex = re.compile(pattern)
    for file_path in path.rglob(f"*{file_extension}"):
        if any(part.startswith(".") for part in file_path.parts):
            continue
        try:
            content = file_path.read_text()
            for i, line in enumerate(content.split("\n"), 1):
                if regex.search(line):
                    results.append(f"{file_path}:{i}: {line.strip()[:100]}")
        except (OSError, UnicodeDecodeError):
            continue

    if not results:
        return f"No matches for '{pattern}' in {directory}"
    return "\n".join(results[:50])


def git_diff(staged: bool = False) -> str:
    """Get git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return f"git diff failed: {result.stderr}"
        return result.stdout or "No changes."
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"Error running git diff: {e}"


def read_file(path: str, max_lines: int = 200) -> str:
    """Read contents of a file."""
    file_path = Path(path)
    if not file_path.exists():
        return f"File not found: {path}"
    try:
        lines = file_path.read_text().split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            return f"{content}\n... ({len(lines) - max_lines} more lines)"
        return "\n".join(lines)
    except (OSError, UnicodeDecodeError) as e:
        return f"Error reading file: {e}"


def count_complexity(code: str) -> str:
    """Estimate cyclomatic complexity of Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"Syntax error: {e}"

    complexities: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                    complexity += 1
                if isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            complexities.append(f"{node.name}: complexity={complexity}")

    if not complexities:
        return "No functions found."
    return "\n".join(complexities)
