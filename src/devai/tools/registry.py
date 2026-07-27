"""Tool registry for DevAI agents."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, get_type_hints

from devai.core.exceptions import ToolError
from devai.core.models import Tool


class ToolRegistry:
    """Registry for agent tools with automatic schema generation."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., str]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(self, func: Callable[..., str], name: str | None = None) -> None:
        """Register a function as a tool."""
        tool_name = name or func.__name__
        self._tools[tool_name] = func
        self._schemas[tool_name] = self._generate_schema(func, tool_name)

    def _generate_schema(self, func: Callable[..., str], name: str) -> Tool:
        sig = inspect.signature(func)
        hints = get_type_hints(func)
        properties: dict[str, Any] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            param_type = hints.get(param_name, str)
            type_map = {str: "string", int: "integer", float: "number", bool: "boolean"}
            json_type = type_map.get(param_type, "string")
            properties[param_name] = {"type": json_type}
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        parameters: dict[str, Any] = {
            "type": "object",
            "properties": properties,
        }
        if required:
            parameters["required"] = required

        doc = inspect.getdoc(func) or f"Execute {name}"
        return Tool(name=name, description=doc.split("\n")[0], parameters=parameters)

    def get_tools(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        try:
            return self._tools[name](**arguments)
        except Exception as e:
            raise ToolError(f"Tool '{name}' failed: {e}") from e

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)
