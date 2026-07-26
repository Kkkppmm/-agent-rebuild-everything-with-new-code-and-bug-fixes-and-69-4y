"""Prompt template system."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PromptTemplate:
    """A template with {variable} placeholders."""

    template: str
    input_variables: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.input_variables:
            self.input_variables = _extract_variables(self.template)

    def format(self, **kwargs: Any) -> str:
        missing = set(self.input_variables) - set(kwargs)
        if missing:
            raise KeyError(f"Missing template variables: {missing}")
        return self.template.format(**{k: kwargs[k] for k in self.input_variables})

    def partial(self, **kwargs: Any) -> PromptTemplate:
        remaining = [v for v in self.input_variables if v not in kwargs]
        formatted = self.template
        for key, value in kwargs.items():
            formatted = formatted.replace(f"{{{key}}}", str(value))
        return PromptTemplate(template=formatted, input_variables=remaining)

    @classmethod
    def from_messages(cls, messages: list[tuple[str, str]]) -> list[PromptTemplate]:
        return [cls(template=content, input_variables=_extract_variables(content)) for role, content in messages]


def _extract_variables(template: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\{(\w+)\}", template)))
