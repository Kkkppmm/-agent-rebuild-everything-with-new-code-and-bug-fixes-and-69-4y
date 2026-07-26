"""Prompt templates for DevAI."""

import re
from typing import Any


class PromptTemplate:
    """A template with variable substitution."""

    def __init__(self, template: str) -> None:
        self.template = template
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
        result = self.template
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", str(value))
        return PromptTemplate(result)
