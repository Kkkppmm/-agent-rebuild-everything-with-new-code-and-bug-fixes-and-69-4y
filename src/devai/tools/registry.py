"""Tool registry for agent tool-calling."""

import json
from typing import Any, Callable

from devai.core.exceptions import ToolError
from devai.core.models import Tool


class ToolRegistry:
    """Register and execute tools for AI agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        description: str,
        parameters: dict[str, Any],
    ) -> None:
        self._tools[name] = fn
        self._schemas[name] = Tool(
            name=name,
            description=description,
            parameters=parameters,
        )

    def get_tools(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        try:
            result = self._tools[name](**arguments)
            if not isinstance(result, str):
                result = json.dumps(result, default=str)
            return result
        except Exception as exc:
            raise ToolError(f"Tool '{name}' failed: {exc}") from exc

    def __len__(self) -> int:
        return len(self._tools)
