"""Registry for custom and built-in prompt templates."""

from __future__ import annotations

from typing import Iterator

from devai.prompts import PromptTemplate
from devai.prompts import templates as builtin


class PromptRegistry:
    """Register, discover, and run custom prompt templates.

    Built-in DevAI prompts are available by default. Register project-specific
    templates to extend :class:`~devai.assistant.CodeAssistant` workflows.

    Example::

        registry = PromptRegistry()
        registry.register(
            "api_error",
            PromptTemplate(
                system="You explain API errors clearly.",
                template="Explain this API error: $error\\nContext: $context",
                input_variables=["error", "context"],
            ),
        )
        prompt = registry.get("api_error")
    """

    def __init__(self, *, include_builtins: bool = True) -> None:
        self._prompts: dict[str, PromptTemplate] = {}
        if include_builtins:
            self._load_builtins()

    def _load_builtins(self) -> None:
        for name in dir(builtin):
            if name.startswith("_"):
                continue
            value = getattr(builtin, name)
            if isinstance(value, PromptTemplate):
                self._prompts[name.lower()] = value

    def register(self, name: str, template: PromptTemplate, *, overwrite: bool = False) -> None:
        """Register a prompt template by name."""
        key = name.lower()
        if key in self._prompts and not overwrite:
            raise ValueError(f"Prompt '{name}' is already registered")
        self._prompts[key] = template

    def get(self, name: str) -> PromptTemplate:
        """Return a registered prompt template."""
        key = name.lower()
        if key not in self._prompts:
            raise KeyError(f"Unknown prompt: {name}")
        return self._prompts[key]

    def list(self) -> list[str]:
        """List registered prompt names."""
        return sorted(self._prompts)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._prompts

    def __iter__(self) -> Iterator[str]:
        return iter(self.list())

    def unregister(self, name: str) -> None:
        """Remove a registered prompt."""
        key = name.lower()
        if key not in self._prompts:
            raise KeyError(f"Unknown prompt: {name}")
        del self._prompts[key]
