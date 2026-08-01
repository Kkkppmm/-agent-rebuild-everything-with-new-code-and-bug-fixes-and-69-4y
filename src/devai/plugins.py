"""Plugin system for extending CodeAssistant with custom actions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class PluginRegistry:
    """Registry of custom assistant actions for DevProgram and plugins."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[..., str]] = {}

    def register(self, name: str, handler: Callable[..., str]) -> None:
        """Register a named action handler."""
        if not name.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Invalid plugin name: {name}")
        self._handlers[name] = handler

    def unregister(self, name: str) -> None:
        """Remove a registered handler."""
        self._handlers.pop(name, None)

    def get(self, name: str) -> Callable[..., str] | None:
        return self._handlers.get(name)

    def call(self, name: str, *args: Any, **kwargs: Any) -> str:
        handler = self._handlers.get(name)
        if handler is None:
            raise KeyError(f"Unknown plugin action: {name}")
        return handler(*args, **kwargs)

    def names(self) -> list[str]:
        return sorted(self._handlers.keys())

    def extend_program_actions(self, base: frozenset[str]) -> frozenset[str]:
        """Merge plugin names into a DevProgram action set."""
        return frozenset(base | frozenset(self._handlers.keys()))


def register_builtin_plugins(registry: PluginRegistry, assistant: Any) -> None:
    """Register common assistant methods as plugin actions."""
    registry.register("review", assistant.review)
    registry.register("explain", assistant.explain)
    registry.register("security", assistant.security)
    registry.register("generate", assistant.generate)
