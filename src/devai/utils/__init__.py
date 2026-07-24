"""Utility functions for text and token handling."""

from __future__ import annotations

import re


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token for English)."""
    return max(1, len(text) // 4)


def extract_code_blocks(text: str) -> list[tuple[str, str]]:
    """Extract fenced code blocks as (language, code) pairs."""
    pattern = r"```(\w*)\n(.*?)```"
    return [(lang or "text", code.strip()) for lang, code in re.findall(pattern, text, re.DOTALL)]


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximate token limit."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."
