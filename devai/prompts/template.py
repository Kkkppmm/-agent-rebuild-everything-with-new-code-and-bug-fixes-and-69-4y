"""Prompt template engine with variable substitution."""

from __future__ import annotations

import re
from typing import Any

from devai.core.models import Message, Role


class PromptTemplate:
  """A reusable prompt with `{variable}` placeholders."""

  _VARIABLE_PATTERN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

  def __init__(self, template: str, *, system: str | None = None) -> None:
    self.template = template
    self.system = system

  def format(self, **variables: Any) -> str:
    """Render the template with provided variables."""
    missing = self.missing_variables(variables)
    if missing:
      raise KeyError(f"Missing template variables: {', '.join(sorted(missing))}")
    return self.template.format(**variables)

  def missing_variables(self, variables: dict[str, Any] | None = None) -> set[str]:
    """Return variable names required but not provided."""
    required = set(self._VARIABLE_PATTERN.findall(self.template))
    provided = set((variables or {}).keys())
    return required - provided

  def to_messages(self, **variables: Any) -> list[Message]:
    """Render and convert to chat messages."""
    messages: list[Message] = []
    if self.system:
      messages.append(Message(role=Role.SYSTEM, content=self.system))
    messages.append(Message(role=Role.USER, content=self.format(**variables)))
    return messages

  @classmethod
  def from_messages(cls, system: str, user: str) -> PromptTemplate:
    """Create a template from separate system and user strings."""
    return cls(user, system=system)

  def __repr__(self) -> str:
    preview = self.template[:40] + ("..." if len(self.template) > 40 else "")
    return f"PromptTemplate({preview!r})"
