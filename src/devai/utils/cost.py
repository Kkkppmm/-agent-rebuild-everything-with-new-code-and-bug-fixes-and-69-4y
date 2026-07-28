"""Token and cost estimation utilities."""

from __future__ import annotations

from devai.utils.tokens import estimate_tokens

# USD per 1M tokens (input, output) — approximate list prices for budgeting.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-haiku": (0.25, 1.25),
}


def estimate_cost(
    input_text: str,
    output_text: str = "",
    *,
    model: str = "gpt-4o-mini",
) -> dict[str, float | int | str]:
    """Estimate token usage and cost for a prompt/response pair.

    Returns a dict with input_tokens, output_tokens, total_tokens,
    estimated_cost_usd, and model.
    """
    input_tokens = estimate_tokens(input_text)
    output_tokens = estimate_tokens(output_text) if output_text else 0
    total_tokens = input_tokens + output_tokens

    pricing = MODEL_PRICING.get(model)
    if pricing is None:
        # Fall back to gpt-4o-mini pricing for unknown models.
        pricing = MODEL_PRICING["gpt-4o-mini"]
        model_key = model
    else:
        model_key = model

    input_rate, output_rate = pricing
    cost = (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000

    return {
        "model": model_key,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": round(cost, 6),
    }
