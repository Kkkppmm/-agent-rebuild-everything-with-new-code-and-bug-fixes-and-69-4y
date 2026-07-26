"""Text utilities for token estimation and code extraction."""

from __future__ import annotations

import re


def estimate_tokens(text: str, *, chars_per_token: float = 4.0) -> int:
    """Rough token count estimate (useful for context window management)."""
    return max(1, int(len(text) / chars_per_token))


def truncate_to_tokens(text: str, max_tokens: int, *, chars_per_token: float = 4.0) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = int(max_tokens * chars_per_token)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def extract_code_blocks(text: str) -> list[dict[str, str]]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```(\w*)\n(.*?)```"
    blocks = []
    for match in re.finditer(pattern, text, re.DOTALL):
        blocks.append({"language": match.group(1) or "text", "code": match.group(2).strip()})
    return blocks
