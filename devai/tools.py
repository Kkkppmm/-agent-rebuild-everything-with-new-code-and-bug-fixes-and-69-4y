"""Function-calling tool registry."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, get_type_hints

from devai.exceptions import ToolExecutionError


@dataclass
class Tool:
    """A callable tool exposed to the model."""

    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., Any]

    def execute(self, arguments: dict[str, Any]) -> Any:
        return self.fn(**arguments)

    def to_openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolRegistry:
    """Registry of tools for agentic workflows."""

    _tools: dict[str, Tool] = field(default_factory=dict)

    def register(
        self,
        fn: Callable[..., Any] | None = None,
        name: str | None = None,
        description: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> Callable[..., Any] | Tool:
        """Register a function as a tool (decorator or direct call)."""
        if fn is None:
            return lambda f: self.register(f, name=name, description=description, parameters=parameters)

        tool_name = name or fn.__name__
        tool_desc = description or (inspect.getdoc(fn) or f"Execute {tool_name}")
        tool_params = parameters or _infer_parameters(fn)

        tool = Tool(name=tool_name, description=tool_desc, parameters=tool_params, fn=fn)
        self._tools[tool_name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if not tool:
            raise ToolExecutionError(f"Tool not found: {name}")
        try:
            return tool.execute(arguments)
        except Exception as exc:
            raise ToolExecutionError(f"Tool '{name}' failed: {exc}") from exc

    def to_openai_schema(self) -> list[dict[str, Any]]:
        return [t.to_openai_schema() for t in self._tools.values()]

    def __len__(self) -> int:
        return len(self._tools)


def _infer_parameters(fn: Callable[..., Any]) -> dict[str, Any]:
    """Build JSON Schema parameters from function signature."""
    sig = inspect.signature(fn)
    hints = get_type_hints(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []

    type_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }

    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls"):
            continue
        hint = hints.get(param_name, str)
        json_type = type_map.get(hint, "string")
        properties[param_name] = {"type": json_type, "description": f"Parameter {param_name}"}
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema
