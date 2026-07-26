"""Prompt template with variable substitution."""

import re
from typing import Any


class PromptTemplate:
    """A reusable prompt template with {variable} placeholders."""

    def __init__(self, template: str, name: str = "") -> None:
        self.template = template
        self.name = name
        self._variables = set(re.findall(r"\{(\w+)\}", template))

    @property
    def variables(self) -> set[str]:
        return self._variables

    def format(self, **kwargs: Any) -> str:
        missing = self._variables - set(kwargs.keys())
        if missing:
            raise KeyError(f"Missing template variables: {missing}")
        return self.template.format(**kwargs)

    def partial(self, **kwargs: Any) -> "PromptTemplate":
        remaining = {k: v for k, v in kwargs.items() if k in self._variables}
        filled = self.template
        for key, value in remaining.items():
            filled = filled.replace(f"{{{key}}}", str(value))
        return PromptTemplate(filled, name=self.name)
