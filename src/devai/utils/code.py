"""Code extraction utilities."""

from __future__ import annotations

import re


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    pattern = r"```(?:" + (re.escape(language) if language else r"\w*") + r")?\s*\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)


def extract_first_code_block(text: str, language: str | None = None) -> str | None:
    blocks = extract_code_blocks(text, language)
    return blocks[0].strip() if blocks else None
