"""Utility functions."""

from __future__ import annotations

import re


def estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ≈ 4 characters)."""
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximate token limit."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```"
    if language:
        pattern += language
    pattern += r"\s*\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)
