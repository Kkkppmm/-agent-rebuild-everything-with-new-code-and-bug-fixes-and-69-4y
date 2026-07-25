"""Tool registry and decorator for registering callable tools."""

from __future__ import annotations

import inspect
import json
from typing import Any, Callable, get_type_hints

from devai.exceptions import ToolExecutionError
from devai.types import Message, Role, ToolCall, ToolDefinition


def _python_type_to_json_schema(py_type: Any) -> dict[str, Any]:
  """Map simple Python types to JSON Schema types."""
  type_map = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
  }
  if py_type in type_map:
    return {"type": type_map[py_type]}
  if hasattr(py_type, "__origin__"):
    origin = py_type.__origin__
    if origin is list:
      return {"type": "array"}
    if origin is dict:
      return {"type": "object"}
  return {"type": "string"}


def _build_parameters(func: Callable) -> dict[str, Any]:
  sig = inspect.signature(func)
  hints = get_type_hints(func)
  properties: dict[str, Any] = {}
  required: list[str] = []

  for name, param in sig.parameters.items():
    if name in ("self", "cls"):
      continue
    prop = _python_type_to_json_schema(hints.get(name, str))
    properties[name] = prop
    if param.default is inspect.Parameter.empty:
      required.append(name)

  return {
    "type": "object",
    "properties": properties,
    "required": required,
  }


class ToolRegistry:
  """Registry for tools that can be invoked by agents and chat."""

  def __init__(self) -> None:
    self._tools: dict[str, ToolDefinition] = {}

  def register(
    self,
    func: Callable | None = None,
    *,
    name: str | None = None,
    description: str | None = None,
  ) -> Callable:
    """Register a function as a tool, usable as decorator or direct call."""

    def decorator(fn: Callable) -> Callable:
      tool_name = name or fn.__name__
      tool_desc = description or (inspect.getdoc(fn) or f"Tool: {tool_name}")
      definition = ToolDefinition(
        name=tool_name,
        description=tool_desc,
        parameters=_build_parameters(fn),
        func=fn,
      )
      self._tools[tool_name] = definition
      return fn

    if func is not None:
      return decorator(func)
    return decorator

  def tool(
    self,
    name: str | None = None,
    description: str | None = None,
  ) -> Callable:
    """Decorator alias for register."""
    return self.register(name=name, description=description)

  def get(self, name: str) -> ToolDefinition | None:
    return self._tools.get(name)

  def list_tools(self) -> list[ToolDefinition]:
    return list(self._tools.values())

  def schemas(self) -> list[dict[str, Any]]:
    return [t.to_schema() for t in self._tools.values()]

  async def execute(self, tool_call: ToolCall) -> str:
    """Execute a tool call and return the result as a string."""
    tool = self._tools.get(tool_call.name)
    if not tool or not tool.func:
      raise ToolExecutionError(f"Tool not found: {tool_call.name}")

    try:
      result = tool.func(**tool_call.arguments)
      if inspect.isawaitable(result):
        result = await result
      if isinstance(result, str):
        return result
      return json.dumps(result, default=str)
    except ToolExecutionError:
      raise
    except Exception as exc:
      raise ToolExecutionError(f"Tool '{tool_call.name}' failed: {exc}") from exc

  async def execute_all(self, tool_calls: list[ToolCall]) -> list[Message]:
    """Execute multiple tool calls and return tool result messages."""
    messages: list[Message] = []
    for call in tool_calls:
      result = await self.execute(call)
      messages.append(
        Message(
          role=Role.TOOL,
          content=result,
          tool_call_id=call.id,
          name=call.name,
        )
      )
    return messages


# Global default registry
default_registry = ToolRegistry()
