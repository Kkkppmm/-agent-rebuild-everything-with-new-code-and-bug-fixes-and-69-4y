"""Tool registry for agent tool-calling."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, get_type_hints

from devai.core.exceptions import ToolError
from devai.core.messages import ToolDefinition


class ToolRegistry:
    """Register and execute callable tools for agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._definitions: dict[str, ToolDefinition] = {}

    def register(
        self,
        func: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[..., Any]:
        """Register a function as a tool, usable as a decorator."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            tool_desc = description or (fn.__doc__ or f"Tool: {tool_name}").strip().split("\n")[0]
            params = _build_parameters_schema(fn)
            self._tools[tool_name] = fn
            self._definitions[tool_name] = ToolDefinition(
                name=tool_name,
                description=tool_desc,
                parameters=params,
            )
            return fn

        if func is not None:
            return decorator(func)
        return decorator

    def get_definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        try:
            result = self._tools[name](**arguments)
            return result if isinstance(result, str) else json.dumps(result, default=str)
        except Exception as exc:
            raise ToolError(f"Tool '{name}' failed: {exc}") from exc

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)


def _build_parameters_schema(fn: Callable[..., Any]) -> dict[str, Any]:
    sig = inspect.signature(fn)
    hints = get_type_hints(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []

    type_map = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}

    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls"):
            continue
        annotation = hints.get(param_name, str)
        json_type = type_map.get(annotation, "string")
        properties[param_name] = {"type": json_type, "description": f"Parameter {param_name}"}
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {"type": "object", "properties": properties, "required": required}
