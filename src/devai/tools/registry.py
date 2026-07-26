"""Tool registry for agent tool-calling."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from devai.core.exceptions import ToolExecutionError
from devai.core.models import ToolDefinition
from devai.tools.code_utils import BUILTIN_TOOLS


class ToolRegistry:
    """Registry of tools available to agents."""

    def __init__(self):
        self._tools: dict[str, dict[str, Any]] = {}

    def register(
        self,
        name: str,
        fn: Callable[..., str],
        description: str,
        parameters: dict[str, Any],
    ) -> None:
        """Register a custom tool."""
        self._tools[name] = {"fn": fn, "description": description, "parameters": parameters}

    def register_builtins(self) -> None:
        """Register all built-in developer tools."""
        for name, spec in BUILTIN_TOOLS.items():
            self._tools[name] = spec

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def get(self, name: str) -> dict[str, Any] | None:
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    def get_definitions(self) -> list[ToolDefinition]:
        """Get tool definitions for LLM tool-calling."""
        return [
            ToolDefinition(
                name=name,
                description=spec["description"],
                parameters=spec["parameters"],
            )
            for name, spec in self._tools.items()
        ]

    def execute(self, name: str, arguments: str | dict[str, Any]) -> str:
        """Execute a tool by name with JSON arguments."""
        spec = self._tools.get(name)
        if not spec:
            raise ToolExecutionError(f"Unknown tool: {name}")

        if isinstance(arguments, str):
            try:
                args = json.loads(arguments)
            except json.JSONDecodeError as exc:
                raise ToolExecutionError(f"Invalid JSON arguments: {exc}") from exc
        else:
            args = arguments

        try:
            return spec["fn"](**args)
        except TypeError as exc:
            raise ToolExecutionError(f"Tool {name} argument error: {exc}") from exc
        except Exception as exc:
            raise ToolExecutionError(f"Tool {name} failed: {exc}") from exc

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
