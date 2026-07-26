"""Text utilities for token estimation and code extraction."""

import re
from typing import Optional


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token for English)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximate token limit."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def extract_code_blocks(text: str, language: Optional[str] = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```(?:(\w+)\s*\n)?(.*?)```"
    blocks = []
    for match in re.finditer(pattern, text, re.DOTALL):
        lang = match.group(1)
        code = match.group(2).strip()
        if language is None or lang == language:
            blocks.append(code)
    return blocks
