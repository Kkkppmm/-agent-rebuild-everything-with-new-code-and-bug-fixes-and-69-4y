"""Prompt template system."""

from __future__ import annotations

from string import Template
from typing import Any


class PromptTemplate:
    """Simple string template for LLM prompts."""

    def __init__(self, template: str) -> None:
        self.template = template

    def format(self, **kwargs: Any) -> str:
        return Template(self.template).safe_substitute(**kwargs)

    def __call__(self, **kwargs: Any) -> str:
        return self.format(**kwargs)
