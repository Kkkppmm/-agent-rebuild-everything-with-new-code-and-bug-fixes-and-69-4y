"""Utility functions for token estimation and text processing."""

from __future__ import annotations

import math
import re


def estimate_tokens(text: str) -> int:
    """Rough token count estimate (≈4 chars per token for English text)."""
    if not text:
        return 0
    return max(1, math.ceil(len(text) / 4))


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to an approximate token limit."""
    char_limit = max_tokens * 4
    if len(text) <= char_limit:
        return text
    return text[:char_limit] + "\n... (truncated)"


def extract_code_blocks(text: str) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```(?:\w+)?\n(.*?)```"
    return [match.strip() for match in re.findall(pattern, text, re.DOTALL)]
