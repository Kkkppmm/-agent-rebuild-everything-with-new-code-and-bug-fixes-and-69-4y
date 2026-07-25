"""Utility helpers for DevAI."""

from __future__ import annotations

import re
from typing import NamedTuple


class CodeBlock(NamedTuple):
    language: str
    code: str


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token for English text)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def extract_code_blocks(text: str) -> list[CodeBlock]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```(\w*)\n(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    return [CodeBlock(language=lang or "text", code=code.strip()) for lang, code in matches]


def extract_json(text: str) -> str | None:
    """Try to extract a JSON object from text."""
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        return text[start : end + 1]
    return None
