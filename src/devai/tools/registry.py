"""Tool registry for agent tool-calling."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from devai.core.exceptions import ToolError
from devai.core.models import Tool
from devai.tools import code_utils


class ToolRegistry:
    """Register and execute tools for LLM agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        description: str,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        self._tools[name] = fn
        self._schemas[name] = Tool(
            name=name,
            description=description,
            parameters=parameters
            or {
                "type": "object",
                "properties": {},
                "required": [],
            },
        )

    def get_schemas(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any] | str) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        try:
            result = self._tools[name](**arguments)
            return str(result) if not isinstance(result, str) else result
        except Exception as e:
            raise ToolError(f"Tool '{name}' failed: {e}") from e

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)


def default_registry() -> ToolRegistry:
    """Create a registry with built-in developer tools."""
    registry = ToolRegistry()
    registry.register(
        "explain_code",
        code_utils.explain_code,
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
        code_utils.lint_python,
        "Run basic Python lint checks on code",
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
        code_utils.search_code,
        "Search for a regex pattern in source files",
        {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Directory to search"},
                "pattern": {"type": "string", "description": "Regex pattern"},
                "file_glob": {"type": "string", "description": "File glob", "default": "*.py"},
            },
            "required": ["directory", "pattern"],
        },
    )
    registry.register(
        "git_diff",
        code_utils.git_diff,
        "Get the current git diff",
        {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Working directory"},
            },
            "required": [],
        },
    )
    registry.register(
        "read_file",
        code_utils.read_file,
        "Read contents of a file",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "max_lines": {"type": "integer", "description": "Max lines to read", "default": 500},
            },
            "required": ["path"],
        },
    )
    registry.register(
        "count_complexity",
        code_utils.count_complexity,
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
