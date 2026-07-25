"""Prompt template utilities."""

from __future__ import annotations

import re
from string import Template
from typing import Any


class PromptTemplate:
  """Simple prompt template with variable substitution.

  Supports both ``{var}`` and ``$var`` style placeholders.
  """

  def __init__(self, template: str) -> None:
    self.template = template
    self._brace_vars = set(re.findall(r"\{(\w+)\}", template))

  def format(self, **kwargs: Any) -> str:
    """Format the template with provided variables."""
    result = self.template
    for key, value in kwargs.items():
      result = result.replace(f"{{{key}}}", str(value))
    # Also support $var style via string.Template
    dollar_vars = {k: str(v) for k, v in kwargs.items()}
    try:
      result = Template(result).safe_substitute(dollar_vars)
    except Exception:
      pass
    return result

  def required_variables(self) -> set[str]:
    return self._brace_vars

  @classmethod
  def from_file(cls, path: str) -> PromptTemplate:
    with open(path, encoding="utf-8") as f:
      return cls(f.read())


def chain_prompts(*parts: str, separator: str = "\n\n") -> str:
  """Join multiple prompt parts into a single string."""
  return separator.join(p.strip() for p in parts if p.strip())
