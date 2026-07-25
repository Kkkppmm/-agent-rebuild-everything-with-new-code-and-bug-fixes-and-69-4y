"""Prompt template utilities."""

from __future__ import annotations

import re
from typing import Any


class PromptTemplate:
  """Simple template with {variable} substitution."""

  def __init__(self, template: str, *, required: list[str] | None = None) -> None:
    self.template = template
    self.required = required or self._extract_variables(template)

  @staticmethod
  def _extract_variables(template: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\{(\w+)\}", template)))

  def format(self, **kwargs: Any) -> str:
    """Render the template with provided variables."""
    missing = [v for v in self.required if v not in kwargs]
    if missing:
      raise ValueError(f"Missing template variables: {', '.join(missing)}")
    return self.template.format(**kwargs)

  def partial(self, **kwargs: Any) -> PromptTemplate:
    """Return a new template with some variables pre-filled."""
    filled = self.template
    for key, value in kwargs.items():
      filled = filled.replace(f"{{{key}}}", str(value))
    return PromptTemplate(filled)

  def __repr__(self) -> str:
    preview = self.template[:50] + ("..." if len(self.template) > 50 else "")
    return f"PromptTemplate({preview!r})"
