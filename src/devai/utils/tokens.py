"""Token and code utility functions."""

from __future__ import annotations

import re


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token for English text)."""
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    if language:
        pattern = rf"```{{1,3}}{language}\s*\n(.*?)```"
    else:
        pattern = r"```(?:\w+)?\s*\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)
