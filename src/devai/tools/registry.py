"""Tool registry for agent tool calling."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, get_type_hints

from devai.core.exceptions import ToolError
from devai.core.models import Tool


class ToolRegistry:
    """Register and execute callable tools for agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[..., Any]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or func.__name__
            tool_desc = description or (func.__doc__ or "").strip().split("\n")[0]
            params = self._build_parameters(func)
            self._tools[tool_name] = func
            self._schemas[tool_name] = Tool(
                name=tool_name,
                description=tool_desc,
                parameters=params,
            )
            return func

        if fn is not None:
            return decorator(fn)
        return decorator

    def _build_parameters(self, func: Callable[..., Any]) -> dict[str, Any]:
        sig = inspect.signature(func)
        hints = get_type_hints(func)
        properties: dict[str, Any] = {}
        required: list[str] = []

        type_map = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array"}

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            hint = hints.get(param_name, str)
            prop: dict[str, Any] = {"type": type_map.get(hint, "string")}
            if param.default is inspect.Parameter.empty:
                required.append(param_name)
            properties[param_name] = prop

        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return schema

    def get_tools(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any] | str) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        try:
            result = self._tools[name](**arguments)
            return str(result) if not isinstance(result, str) else result
        except Exception as exc:
            raise ToolError(f"Tool '{name}' failed: {exc}") from exc

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)
