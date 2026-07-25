"""Prompt template utilities."""

from __future__ import annotations

import re
from string import Template
from typing import Any


class PromptTemplate:
    """
    Reusable prompt templates with variable substitution.

    Supports ``{var}`` brace syntax and ``$var`` dollar syntax.

    Example::

        tpl = PromptTemplate("Write a {language} function to {task}.")
        prompt = tpl.format(language="Python", task="sort a list")
    """

    _BRACE_PATTERN = re.compile(r"\{(\w+)\}")

    def __init__(self, template: str):
        self.template = template

    def format(self, **kwargs: Any) -> str:
        """Substitute variables using brace syntax."""
        def replacer(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in kwargs:
                raise KeyError(f"Missing template variable: {key}")
            return str(kwargs[key])

        return self._BRACE_PATTERN.sub(replacer, self.template)

    def format_dollar(self, **kwargs: Any) -> str:
        """Substitute variables using $var syntax."""
        return Template(self.template).safe_substitute(**kwargs)

    def partial(self, **kwargs: Any) -> PromptTemplate:
        """Create a new template with some variables pre-filled."""
        filled = self.format(**kwargs)
        return PromptTemplate(filled)

    def __str__(self) -> str:
        return self.template
