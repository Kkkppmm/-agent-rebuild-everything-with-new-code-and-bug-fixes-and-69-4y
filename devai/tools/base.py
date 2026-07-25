"""Tool base classes and registry."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, get_type_hints

from devai.core.models import ToolDefinition


def _python_type_to_json_schema(py_type: Any) -> dict[str, Any]:
  """Map basic Python types to JSON Schema fragments."""
  mapping: dict[Any, dict[str, Any]] = {
    str: {"type": "string"},
    int: {"type": "integer"},
    float: {"type": "number"},
    bool: {"type": "boolean"},
    list: {"type": "array"},
    dict: {"type": "object"},
  }
  origin = getattr(py_type, "__origin__", None)
  if origin is list:
    args = getattr(py_type, "__args__", ())
    item_type = args[0] if args else Any
    return {"type": "array", "items": _python_type_to_json_schema(item_type)}
  return mapping.get(py_type, {"type": "string"})


class Tool:
  """Wrap a Python callable as an LLM-invokable tool."""

  def __init__(
    self,
    func: Callable[..., Any],
    *,
    name: str | None = None,
    description: str | None = None,
  ) -> None:
    self.func = func
    self.name = name or func.__name__
    self.description = description or (func.__doc__ or "").strip().split("\n")[0]
    self._signature = inspect.signature(func)
    self._hints = get_type_hints(func)

  @property
  def definition(self) -> ToolDefinition:
    """Generate an OpenAI-compatible tool definition from the function signature."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param_name, param in self._signature.parameters.items():
      if param_name in ("self", "cls"):
        continue
      param_type = self._hints.get(param_name, str)
      properties[param_name] = _python_type_to_json_schema(param_type)
      if param.default is inspect.Parameter.empty:
        required.append(param_name)

    return ToolDefinition(
      name=self.name,
      description=self.description,
      parameters={
        "type": "object",
        "properties": properties,
        "required": required,
      },
    )

  def run(self, **kwargs: Any) -> Any:
    """Execute the tool with validated keyword arguments."""
    bound = self._signature.bind_partial(**kwargs)
    bound.apply_defaults()
    return self.func(*bound.args, **bound.kwargs)

  def run_json(self, arguments: str | dict[str, Any]) -> str:
    """Execute from JSON-encoded arguments and return a string result."""
    if isinstance(arguments, str):
      parsed = json.loads(arguments) if arguments else {}
    else:
      parsed = arguments
    result = self.run(**parsed)
    if isinstance(result, str):
      return result
    return json.dumps(result, default=str)

  def __call__(self, **kwargs: Any) -> Any:
    return self.run(**kwargs)

  def __repr__(self) -> str:
    return f"Tool(name={self.name!r})"
