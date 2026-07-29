"""Utility functions for DevAI."""

from __future__ import annotations

import re

from devai.utils.budget import BudgetedLLMClient, BudgetSnapshot, TokenBudget
from devai.utils.diff import get_git_diff, parse_changed_files, read_diff, summarize_diff
from devai.utils.tokens import (
    count_message_tokens,
    estimate_cost,
    estimate_message_cost,
    estimate_tokens,
    format_cost,
    truncate_to_tokens,
)

__all__ = [
    "BudgetedLLMClient",
    "BudgetSnapshot",
    "TokenBudget",
    "count_message_tokens",
    "estimate_cost",
    "estimate_message_cost",
    "estimate_tokens",
    "extract_code_blocks",
    "format_cost",
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
