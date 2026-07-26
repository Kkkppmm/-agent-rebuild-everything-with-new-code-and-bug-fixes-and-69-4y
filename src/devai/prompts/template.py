"""Prompt template system."""

from __future__ import annotations

import re
from typing import Any


class PromptTemplate:
    """Simple template with {variable} substitution."""

    def __init__(self, template: str) -> None:
        self.template = template
        self._variables = set(re.findall(r"\{(\w+)\}", template))

    @property
    def variables(self) -> set[str]:
        return self._variables

    def format(self, **kwargs: Any) -> str:
        missing = self._variables - set(kwargs)
        if missing:
            raise KeyError(f"Missing template variables: {missing}")
        return self.template.format(**kwargs)

    def partial(self, **kwargs: Any) -> PromptTemplate:
        """Return a new template with some variables pre-filled."""
        filled = self.template
        for key, value in kwargs.items():
            filled = filled.replace(f"{{{key}}}", str(value))
        return PromptTemplate(filled)
