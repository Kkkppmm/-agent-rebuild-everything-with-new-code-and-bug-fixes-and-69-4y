"""Utility functions for DevAI."""

from __future__ import annotations

import re

from devai.utils.diff import get_git_diff, parse_changed_files, read_diff, summarize_diff

__all__ = [
    "estimate_tokens",
    "estimate_cost",
    "extract_code_blocks",
    "get_git_diff",
    "parse_changed_files",
    "read_diff",
    "summarize_diff",
    "truncate_to_tokens",
]


def estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ≈ 4 characters for English)."""
    return max(1, len(text) // 4)


# Approximate USD per 1M tokens (input, output) for common models
_MODEL_COSTS: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-haiku": (0.25, 1.25),
}


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "gpt-4o-mini",
) -> float:
    """Estimate API cost in USD for a given token count and model."""
    for key, (input_rate, output_rate) in _MODEL_COSTS.items():
        if key in model:
            input_cost = (input_tokens / 1_000_000) * input_rate
            output_cost = (output_tokens / 1_000_000) * output_rate
            return round(input_cost + output_cost, 6)
    # Default to gpt-4o-mini pricing
    input_rate, output_rate = _MODEL_COSTS["gpt-4o-mini"]
    return round(
        (input_tokens / 1_000_000) * input_rate + (output_tokens / 1_000_000) * output_rate,
        6,
    )


def extract_code_blocks(text: str, language: str | None = None) -> list[str]:
    """Extract fenced code blocks from markdown text."""
    if language:
        pattern = rf"```{re.escape(language)}\n(.*?)```"
    else:
        pattern = r"```(?:\w+)?\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"
