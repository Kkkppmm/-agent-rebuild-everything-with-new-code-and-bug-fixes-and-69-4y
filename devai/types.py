"""Shared type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Usage:
    """Token usage statistics from an API call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class ChatResponse:
    """Response from a chat completion."""

    content: str
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """Alias for content."""
        return self.content
