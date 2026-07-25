"""Prompt template utilities."""

from __future__ import annotations

import re
from string import Template
from typing import Any

from devai.types import Message, Role


class PromptTemplate:
    """Lightweight prompt template with ``{variable}`` substitution."""

    def __init__(self, template: str):
        self.template = template
        self._fields = set(re.findall(r"\{(\w+)\}", template))

    @property
    def variables(self) -> set[str]:
        return self._fields

    def format(self, **kwargs: Any) -> str:
        missing = self._fields - set(kwargs)
        if missing:
            raise KeyError(f"Missing template variables: {', '.join(sorted(missing))}")
        return self.template.format(**kwargs)

    def to_messages(self, role: Role | str = Role.USER, **kwargs: Any) -> list[Message]:
        return [Message(role=role, content=self.format(**kwargs))]


class ChatPrompt:
    """Multi-turn prompt builder for chat models."""

    def __init__(self):
        self._messages: list[Message] = []

    def system(self, content: str) -> ChatPrompt:
        self._messages.append(Message(role=Role.SYSTEM, content=content))
        return self

    def user(self, content: str) -> ChatPrompt:
        self._messages.append(Message(role=Role.USER, content=content))
        return self

    def assistant(self, content: str) -> ChatPrompt:
        self._messages.append(Message(role=Role.ASSISTANT, content=content))
        return self

    def add(self, role: Role | str, content: str) -> ChatPrompt:
        self._messages.append(Message(role=role, content=content))
        return self

    def build(self) -> list[Message]:
        return list(self._messages)

    def __len__(self) -> int:
        return len(self._messages)


def render(template: str, **kwargs: Any) -> str:
    """Safe dollar-sign template rendering using ``string.Template``."""
    return Template(template).safe_substitute(**kwargs)
