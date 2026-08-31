"""Token counting and cost estimation utilities."""

from __future__ import annotations

from devai.core.models import Message

# USD per 1M tokens (input, output)
MODEL_PRICING: dict[str, dict[str, float]] = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
}


def estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ≈ 4 characters for English)."""
    return max(1, len(text) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


def count_message_tokens(messages: list[Message]) -> int:
    """Estimate total tokens across a list of messages."""
    return sum(estimate_tokens(f"{m.role}: {m.content}") for m in messages)


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "gpt-4o-mini",
) -> float:
    """Estimate LLM call cost in USD."""
    pricing = _resolve_pricing(model)
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    return round(input_cost + output_cost, 6)


def estimate_message_cost(
    messages: list[Message],
    response: str,
    model: str = "gpt-4o-mini",
) -> float:
    """Estimate cost for a single completion from messages and response."""
    return estimate_cost(
        count_message_tokens(messages),
        estimate_tokens(response),
        model=model,
    )


def format_cost(cost_usd: float) -> str:
    """Format a cost value for display."""
    if cost_usd < 0.01:
        return f"${cost_usd:.6f}"
    return f"${cost_usd:.4f}"


def _resolve_pricing(model: str) -> dict[str, float]:
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    for key, pricing in MODEL_PRICING.items():
        if model.startswith(key):
            return pricing
    return MODEL_PRICING["gpt-4o-mini"]
