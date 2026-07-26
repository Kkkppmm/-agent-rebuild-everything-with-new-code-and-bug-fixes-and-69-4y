"""Prompt template engine."""

from __future__ import annotations

import re
from typing import Any


class PromptTemplate:
    """Simple template with {variable} substitution and partial formatting."""

    def __init__(self, template: str):
        self.template = template
        self._variables = set(re.findall(r"\{(\w+)\}", template))

    @property
    def variables(self) -> set[str]:
        return self._variables

    def format(self, **kwargs: Any) -> str:
        """Format the template with provided variables."""
        missing = self._variables - set(kwargs.keys()) - {""}
        # Allow optional variables by defaulting to empty string
        filled = {var: kwargs.get(var, "") for var in self._variables}
        return self.template.format(**filled)

    def partial(self, **kwargs: Any) -> PromptTemplate:
        """Return a new template with some variables pre-filled."""
        result = self.template
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", str(value))
        return PromptTemplate(result)

    def __repr__(self) -> str:
        preview = self.template[:50] + "..." if len(self.template) > 50 else self.template
        return f"PromptTemplate({preview!r})"
