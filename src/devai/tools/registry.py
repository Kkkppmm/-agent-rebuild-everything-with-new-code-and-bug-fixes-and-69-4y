"""Tool registry for agent tool-calling."""

from __future__ import annotations

import inspect
import json
from typing import Any, Callable

from devai.core.models import Tool
from devai.core.exceptions import ToolExecutionError


class ToolRegistry:
    """Registry of callable tools that can be passed to LLM agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        func: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> Callable[..., Any]:
        """Register a function as a tool (usable as decorator)."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            tool_desc = description or (fn.__doc__ or "").strip().split("\n")[0]
            tool_params = parameters or self._infer_schema(fn)
            self._tools[tool_name] = fn
            self._schemas[tool_name] = Tool(
                name=tool_name,
                description=tool_desc,
                parameters=tool_params,
            )
            return fn

        if func is not None:
            return decorator(func)
        return decorator

    def get_tools(self) -> list[Tool]:
        return list(self._schemas.values())

    def get_tool_names(self) -> list[str]:
        return list(self._tools.keys())

    async def execute(self, name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool by name and return the result as a string."""
        if name not in self._tools:
            raise ToolExecutionError(f"Unknown tool: {name}")
        func = self._tools[name]
        try:
            if inspect.iscoroutinefunction(func):
                result = await func(**arguments)
            else:
                result = func(**arguments)
            if isinstance(result, str):
                return result
            return json.dumps(result, indent=2, default=str)
        except Exception as e:
            raise ToolExecutionError(f"Tool '{name}' failed: {e}") from e

    def execute_sync(self, name: str, arguments: dict[str, Any]) -> str:
        import asyncio

        return asyncio.run(self.execute(name, arguments))

    def _infer_schema(self, fn: Callable[..., Any]) -> dict[str, Any]:
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
            properties[param_name] = prop
            if param.default is inspect.Parameter.empty:
                required.append(param_name)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
