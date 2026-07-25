"""Reusable prompt templates with variable substitution."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PromptTemplate:
    """A template string with `{variable}` placeholders."""

    template: str
    input_variables: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.input_variables:
            self.input_variables = sorted(set(re.findall(r"\{(\w+)\}", self.template)))

    def format(self, **kwargs: Any) -> str:
        missing = [v for v in self.input_variables if v not in kwargs]
        if missing:
            raise KeyError(f"Missing template variables: {missing}")
        return self.template.format(**kwargs)

    def partial(self, **kwargs: Any) -> PromptTemplate:
        """Return a new template with some variables pre-filled."""
        filled = self.format(**kwargs) if all(k in kwargs for k in self.input_variables) else self.template
        remaining = [v for v in self.input_variables if v not in kwargs]
        return PromptTemplate(template=filled, input_variables=remaining)
