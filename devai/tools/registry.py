"""Tool registry for agent workflows."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from devai.core.models import ToolDefinition
from devai.tools.base import Tool


class ToolRegistry:
  """Register and dispatch tools by name."""

  def __init__(self) -> None:
    self._tools: dict[str, Tool] = {}

  def register(
    self,
    func: Callable[..., Any] | None = None,
    *,
    name: str | None = None,
    description: str | None = None,
  ) -> Callable[..., Any] | Tool:
    """Register a function as a tool (decorator or direct call)."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
      tool = Tool(fn, name=name, description=description)
      self._tools[tool.name] = tool
      return fn

    if func is not None:
      return decorator(func)
    return decorator

  def add(self, tool: Tool) -> None:
    """Add a pre-built Tool instance."""
    self._tools[tool.name] = tool

  def get(self, name: str) -> Tool:
    if name not in self._tools:
      raise KeyError(f"Tool not found: {name}")
    return self._tools[name]

  def run(self, name: str, arguments: dict[str, Any] | str) -> str:
    """Execute a tool by name."""
    return self.get(name).run_json(arguments)

  def definitions(self) -> list[ToolDefinition]:
    """Return all tool definitions for the LLM API."""
    return [tool.definition for tool in self._tools.values()]

  def __contains__(self, name: str) -> bool:
    return name in self._tools

  def __len__(self) -> int:
    return len(self._tools)

  def __iter__(self):
    return iter(self._tools.values())

  def __repr__(self) -> str:
    return f"ToolRegistry(tools={list(self._tools.keys())})"
