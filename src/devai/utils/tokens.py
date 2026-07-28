"""Token estimation utilities."""

from __future__ import annotations


def estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ≈ 4 characters for English)."""
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"
