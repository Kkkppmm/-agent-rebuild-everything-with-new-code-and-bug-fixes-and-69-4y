"""Prompt templates for DevAI."""

from __future__ import annotations

import re
from typing import Any


class PromptTemplate:
    """Simple template with {variable} substitution."""

    def __init__(self, template: str, *, input_variables: list[str] | None = None):
        self.template = template
        self.input_variables = input_variables or self._extract_variables(template)

    @staticmethod
    def _extract_variables(template: str) -> list[str]:
        return list(dict.fromkeys(re.findall(r"\{(\w+)\}", template)))

    def format(self, **kwargs: Any) -> str:
        missing = set(self.input_variables) - set(kwargs)
        if missing:
            raise KeyError(f"Missing template variables: {missing}")
        return self.template.format(**kwargs)

    def partial(self, **kwargs: Any) -> PromptTemplate:
        remaining = {k: v for k, v in kwargs.items() if k in self.input_variables}
        new_template = self.template
        for key, value in remaining.items():
            new_template = new_template.replace(f"{{{key}}}", str(value))
        new_vars = [v for v in self.input_variables if v not in remaining]
        return PromptTemplate(new_template, input_variables=new_vars)

    def __repr__(self) -> str:
        return f"PromptTemplate(variables={self.input_variables})"
