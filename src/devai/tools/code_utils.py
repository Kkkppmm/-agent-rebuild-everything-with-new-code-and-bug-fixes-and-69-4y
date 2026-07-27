"""Tool registry and built-in developer tools."""

from __future__ import annotations

import ast
import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from devai.core.exceptions import ToolExecutionError
from devai.core.models import ToolDefinition


@dataclass
class Tool:
    """A callable tool with schema metadata."""

    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., str]

    def to_definition(self) -> ToolDefinition:
        return ToolDefinition(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )

    def run(self, **kwargs: Any) -> str:
        try:
            return self.fn(**kwargs)
        except Exception as exc:
            raise ToolExecutionError(f"Tool '{self.name}' failed: {exc}") from exc


class ToolRegistry:
    """Registry for agent tools."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        return [t.to_definition() for t in self._tools.values()]

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        tool = self._tools.get(name)
        if not tool:
            raise ToolExecutionError(f"Unknown tool: {name}")
        return tool.run(**arguments)

    def names(self) -> list[str]:
        return list(self._tools.keys())


def read_file(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    return p.read_text(encoding="utf-8", errors="replace")


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    root = Path(directory)
    if not root.exists():
        return f"Error: directory not found: {directory}"
    regex = re.compile(pattern, re.IGNORECASE)
    matches: list[str] = []
    for path in root.rglob(file_glob):
        if path.is_file():
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    matches.append(f"{path}:{i}: {line.strip()}")
    return "\n".join(matches[:50]) if matches else "No matches found."


def explain_code(code: str, language: str = "python") -> str:
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
            return json.dumps(
                {"functions": functions, "classes": classes, "imports": imports},
                indent=2,
            )
        except SyntaxError as exc:
            return f"Syntax error: {exc}"
    return f"Code analysis for {language}: {len(code)} characters"


def lint_python(code: str) -> str:
    issues: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error at line {exc.lineno}: {exc.msg}"

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef)
            and not node.name.startswith("_")
            and not ast.get_docstring(node)
        ):
            issues.append(f"Missing docstring: {node.name} (line {node.lineno})")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Bare except at line {node.lineno}")

    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 100:
            issues.append(f"Line {i} exceeds 100 characters")
        if line.rstrip() != line:
            issues.append(f"Trailing whitespace on line {i}")

    return "\n".join(issues) if issues else "No lint issues found."


def git_diff(staged: bool = False) -> str:
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        return result.stdout or "No diff output."
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        return f"Error running git diff: {exc}"


def count_complexity(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

    results: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = _cyclomatic_complexity(node)
            results.append(f"{node.name}: complexity={complexity}")
    return "\n".join(results) if results else "No functions found."


def _cyclomatic_complexity(node: ast.AST) -> int:
    complexity = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler, ast.With)):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
    return complexity


def list_files(directory: str, pattern: str = "*") -> str:
    root = Path(directory)
    if not root.exists():
        return f"Error: directory not found: {directory}"
    files = sorted(str(p.relative_to(root)) for p in root.rglob(pattern) if p.is_file())
    return "\n".join(files[:100]) if files else "No files found."


def default_tools() -> list[Tool]:
    return [
        Tool(
            name="read_file",
            description="Read the contents of a file",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path"}},
                "required": ["path"],
            },
            fn=read_file,
        ),
        Tool(
            name="search_code",
            description="Search for a regex pattern in code files",
            parameters={
                "type": "object",
                "properties": {
                    "directory": {"type": "string"},
                    "pattern": {"type": "string"},
                    "file_glob": {"type": "string", "default": "*.py"},
                },
                "required": ["directory", "pattern"],
            },
            fn=lambda directory, pattern, file_glob="*.py": search_code(directory, pattern, file_glob),
        ),
        Tool(
            name="list_files",
            description="List files in a directory matching a glob pattern",
            parameters={
                "type": "object",
                "properties": {
                    "directory": {"type": "string"},
                    "pattern": {"type": "string", "default": "*"},
                },
                "required": ["directory"],
            },
            fn=lambda directory, pattern="*": list_files(directory, pattern),
        ),
        Tool(
            name="explain_code",
            description="Analyze code structure (functions, classes, imports)",
            parameters={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "language": {"type": "string", "default": "python"},
                },
                "required": ["code"],
            },
            fn=explain_code,
        ),
        Tool(
            name="lint_python",
            description="Run basic Python lint checks on code",
            parameters={
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
            fn=lint_python,
        ),
        Tool(
            name="git_diff",
            description="Get the current git diff",
            parameters={
                "type": "object",
                "properties": {"staged": {"type": "boolean", "default": False}},
            },
            fn=lambda staged=False: git_diff(staged),
        ),
        Tool(
            name="count_complexity",
            description="Calculate cyclomatic complexity of Python functions",
            parameters={
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
            fn=count_complexity,
        ),
    ]
