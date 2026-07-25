"""Tool registry and execution helpers."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, get_type_hints

from devai.types import Message, Role, ToolCall, ToolDefinition


def _python_type_to_json(annotation: Any) -> dict[str, str]:
    mapping = {str: "string", int: "integer", float: "number", bool: "boolean"}
    if annotation in mapping:
        return {"type": mapping[annotation]}
    return {"type": "string"}


def function_to_tool(fn: Callable[..., Any]) -> ToolDefinition:
    """Convert a Python function into a ``ToolDefinition`` using its docstring and hints."""
    name = fn.__name__
    description = (inspect.getdoc(fn) or name).strip().split("\n")[0]
    sig = inspect.signature(fn)
    hints = get_type_hints(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls"):
            continue
        properties[param_name] = _python_type_to_json(hints.get(param_name, str))
        if param.default is inspect.Parameter.empty:
            required.append(param_name)
    return ToolDefinition(
        name=name,
        description=description,
        parameters={
            "type": "object",
            "properties": properties,
            "required": required,
        },
    )


class ToolRegistry:
    """Register Python callables and execute model-requested tool calls."""

    def __init__(self):
        self._tools: dict[str, Callable[..., Any]] = {}
        self._definitions: dict[str, ToolDefinition] = {}

    def register(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        definition = function_to_tool(fn)
        self._tools[definition.name] = fn
        self._definitions[definition.name] = definition
        return fn

    def tool(self, fn: Callable[..., Any] | None = None):
        """Decorator: ``@registry.tool`` or ``@registry.tool()``."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return self.register(func)

        if fn is not None:
            return decorator(fn)
        return decorator

    @property
    def definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def execute(self, call: ToolCall) -> Any:
        fn = self._tools.get(call.name)
        if fn is None:
            raise KeyError(f"Unknown tool: {call.name}")
        return fn(**call.arguments)

    def execute_all(self, calls: list[ToolCall]) -> list[Message]:
        results = []
        for call in calls:
            try:
                output = self.execute(call)
                if not isinstance(output, str):
                    output = json.dumps(output)
            except Exception as exc:
                output = f"Error: {exc}"
            results.append(
                Message(role=Role.TOOL, content=output, tool_call_id=call.id, name=call.name)
            )
        return results
