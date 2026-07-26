"""Reusable prompt template with variable substitution."""

from __future__ import annotations

import re
from typing import Any


class PromptTemplate:
    """A template string with {variable} placeholders."""

    def __init__(self, template: str, *, partial: bool = False) -> None:
        self.template = template
        self.partial = partial
        self._variables = set(re.findall(r"\{(\w+)\}", template))

    @property
    def variables(self) -> set[str]:
        return self._variables

    def format(self, **kwargs: Any) -> str:
        """Format the template with the given variables."""
        missing = self._variables - set(kwargs.keys())
        if missing and not self.partial:
            raise KeyError(f"Missing template variables: {missing}")
        return self.template.format(**{k: kwargs.get(k, "") for k in self._variables})

    def __or__(self, other: "PromptTemplate") -> "PromptTemplate":
        """Chain two templates together."""
        return PromptTemplate(self.template + "\n\n" + other.template)

    def __repr__(self) -> str:
        return f"PromptTemplate(variables={self._variables!r})"
