"""Utility functions for DevAI."""

from __future__ import annotations

import re

from devai.utils.cost import estimate_cost
from devai.utils.diff import get_git_diff, parse_changed_files, read_diff, summarize_diff
from devai.utils.tokens import estimate_tokens, truncate_to_tokens

__all__ = [
    "estimate_cost",
    "estimate_tokens",
    "extract_code_blocks",
    "get_git_diff",
    "parse_changed_files",
    "read_diff",
    "summarize_diff",
    "truncate_to_tokens",
]


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    if language:
        pattern = rf"```{re.escape(language)}\n(.*?)```"
    else:
        pattern = r"```(?:\w+)?\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)
