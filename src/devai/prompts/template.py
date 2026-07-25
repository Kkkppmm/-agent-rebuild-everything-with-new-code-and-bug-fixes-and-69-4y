"""Prompt template engine for DevAI."""

from __future__ import annotations

import re
from typing import Any


class PromptTemplate:
    """A template with {variable} placeholders for building LLM prompts."""

    def __init__(self, template: str, *, partial: bool = False):
        self.template = template
        self.partial = partial
        self._variables = set(re.findall(r"\{(\w+)\}", template))

    @property
    def variables(self) -> set[str]:
        return self._variables

    def format(self, **kwargs: Any) -> str:
        """Fill in template variables."""
        missing = self._variables - set(kwargs.keys())
        if missing and not self.partial:
            raise KeyError(f"Missing template variables: {missing}")
        result = self.template
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result

    def __or__(self, other: PromptTemplate) -> PromptTemplate:
        """Chain two templates together."""
        return PromptTemplate(f"{self.template}\n\n{other.template}", partial=True)

    def __repr__(self) -> str:
        preview = self.template[:50] + "..." if len(self.template) > 50 else self.template
        return f"PromptTemplate({preview!r})"
