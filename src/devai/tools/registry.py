"""Tool registry for DevAI agents."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from devai.core.exceptions import ToolError
from devai.core.models import Tool


class ToolRegistry:
    """Registry for callable tools used by agents."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., str]] = {}
        self._schemas: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        fn: Callable[..., str],
        description: str,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        self._tools[name] = fn
        self._schemas[name] = Tool(
            name=name,
            description=description,
            parameters=parameters or {"type": "object", "properties": {}, "required": []},
        )

    def get_schema(self, name: str) -> Tool:
        if name not in self._schemas:
            raise ToolError(f"Tool not found: {name}")
        return self._schemas[name]

    def get_schemas(self) -> list[Tool]:
        return list(self._schemas.values())

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self._tools:
            raise ToolError(f"Tool not found: {name}")
        try:
            return self._tools[name](**arguments)
        except Exception as exc:
            raise ToolError(f"Tool '{name}' failed: {exc}") from exc

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)
