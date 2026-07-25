"""Token and text utilities."""

from __future__ import annotations


def estimate_tokens(text: str, model: str = "gpt-4") -> int:
  """Rough token count estimate (~4 chars per token for English text)."""
  _ = model  # reserved for model-specific tokenizers
  if not text:
    return 0
  return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int, model: str = "gpt-4") -> str:
  """Truncate text to approximately max_tokens."""
  if estimate_tokens(text, model) <= max_tokens:
    return text
  char_limit = max_tokens * 4
  return text[:char_limit] + "..."
