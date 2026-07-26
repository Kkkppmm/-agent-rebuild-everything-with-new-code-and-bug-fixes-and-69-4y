"""Tool registry for registering and executing agent tools."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, get_type_hints

from devai.core.exceptions import ToolExecutionError
from devai.core.models import Tool


class ToolRegistry:
    """Registry for callable tools that agents can invoke."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        func: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[..., Any]:
        """Register a function as a tool (usable as decorator)."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            doc = description or (fn.__doc__ or f"Execute {tool_name}").strip()
            params = self._build_parameters(fn)
            self._tools[tool_name] = fn
            self._schemas[tool_name] = Tool(
                name=tool_name,
                description=doc,
                parameters=params,
            )
            return fn

        if func is not None:
            return decorator(func)
        return decorator

    def _build_parameters(self, fn: Callable[..., Any]) -> dict[str, Any]:
        sig = inspect.signature(fn)
        hints = get_type_hints(fn)
        properties: dict[str, Any] = {}
        required: list[str] = []

        type_map = {str: "string", int: "integer", float: "number", bool: "boolean"}

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            hint = hints.get(param_name, str)
            prop: dict[str, Any] = {"type": type_map.get(hint, "string")}
            properties[param_name] = prop
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {"type": "object", "properties": properties, "required": required}

    def get_tool(self, name: str) -> Tool:
        if name not in self._schemas:
            raise ToolExecutionError(f"Unknown tool: {name}")
        return self._schemas[name]

    def list_tools(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any] | str) -> str:
        """Execute a tool by name with the given arguments."""
        if name not in self._tools:
            raise ToolExecutionError(f"Unknown tool: {name}")
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        try:
            result = self._tools[name](**arguments)
            return str(result) if not isinstance(result, str) else result
        except Exception as exc:
            raise ToolExecutionError(f"Tool '{name}' failed: {exc}") from exc

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
