"""Utility functions for text processing and token estimation."""

from __future__ import annotations

import re


def estimate_tokens(text: str) -> int:
    """Rough token count estimate (≈4 chars per token for English)."""
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```(?:\w+)?\n(.*?)```" if language is None else rf"```{language}\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)


def strip_code_fences(text: str) -> str:
    """Remove markdown code fences from text."""
    text = re.sub(r"^```\w*\n", "", text.strip())
    text = re.sub(r"\n```$", "", text)
    return text.strip()
