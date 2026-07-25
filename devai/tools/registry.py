"""Registry for LLM-callable tools."""

from __future__ import annotations

import inspect
import json
from typing import Any, Callable

from devai.core.models import ToolDefinition


class ToolRegistry:
    """Register Python callables as LLM tools with auto-generated schemas."""

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
        """Decorator or direct call to register a tool."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            tool_desc = description or (fn.__doc__ or "").strip().split("\n")[0]
            params = self._build_parameters(fn)
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

    def _build_parameters(self, fn: Callable[..., Any]) -> dict[str, Any]:
        sig = inspect.signature(fn)
        properties: dict[str, Any] = {}
        required: list[str] = []
        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            prop: dict[str, Any] = {"type": "string"}
            if param.annotation != inspect.Parameter.empty:
                ann = param.annotation
                if ann is int:
                    prop["type"] = "integer"
                elif ann is float:
                    prop["type"] = "number"
                elif ann is bool:
                    prop["type"] = "boolean"
                elif ann is list:
                    prop["type"] = "array"
                elif ann is dict:
                    prop["type"] = "object"
            if param.default is inspect.Parameter.empty:
                required.append(param_name)
            properties[param_name] = prop
        return {"type": "object", "properties": properties, "required": required}

    def get_definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        result = self._tools[name](**arguments)
        if isinstance(result, str):
            return result
        return json.dumps(result, default=str)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)
