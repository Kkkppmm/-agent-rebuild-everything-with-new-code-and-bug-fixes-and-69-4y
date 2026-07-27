"""Text utilities for token estimation and code extraction."""

from __future__ import annotations

import re


def estimate_tokens(text: str) -> int:
  """Rough token count estimate (chars / 4)."""
  return max(1, len(text) // 4)


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
  """Extract fenced code blocks from markdown text."""
  pattern = r"```(?:" + (re.escape(language) if language else r"\w*") + r")?\s*\n(.*?)```"
  return re.findall(pattern, text, re.DOTALL)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
  """Truncate text to approximately max_tokens."""
  max_chars = max_tokens * 4
  if len(text) <= max_chars:
    return text
  return text[:max_chars] + "..."
