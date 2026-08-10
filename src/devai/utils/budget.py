"""Token budget tracking and enforcement for DevAI workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.core.exceptions import BudgetExceededError
from devai.core.models import Message
from devai.utils.tokens import count_message_tokens, estimate_cost, estimate_tokens, format_cost


@dataclass
class BudgetSnapshot:
    """Point-in-time token and cost usage."""

    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    remaining_tokens: int | None
    limit_tokens: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "remaining_tokens": self.remaining_tokens,
            "limit_tokens": self.limit_tokens,
        }


class TokenBudget:
    """Track and enforce token usage across multiple LLM calls.

    Example::

        budget = TokenBudget(max_tokens=8000, model="gpt-4o-mini")
        budget.record_call(messages, response)
        print(budget.snapshot())
    """

    def __init__(
        self,
        *,
        max_tokens: int | None = None,
        max_cost_usd: float | None = None,
        model: str = "gpt-4o-mini",
    ) -> None:
        self.max_tokens = max_tokens
        self.max_cost_usd = max_cost_usd
        self.model = model
        self._input_tokens = 0
        self._output_tokens = 0
        self._call_count = 0

    @property
    def input_tokens(self) -> int:
        return self._input_tokens

    @property
    def output_tokens(self) -> int:
        return self._output_tokens

    @property
    def total_tokens(self) -> int:
        return self._input_tokens + self._output_tokens

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def estimated_cost_usd(self) -> float:
        return estimate_cost(self._input_tokens, self._output_tokens, model=self.model)

    def remaining_tokens(self) -> int | None:
        if self.max_tokens is None:
            return None
        return max(0, self.max_tokens - self.total_tokens)

    def check(self) -> None:
        """Raise BudgetExceededError if limits are exceeded."""
        if self.max_tokens is not None and self.total_tokens > self.max_tokens:
            raise BudgetExceededError(
                f"Token budget exceeded: {self.total_tokens} > {self.max_tokens}"
            )
        if self.max_cost_usd is not None and self.estimated_cost_usd > self.max_cost_usd:
            raise BudgetExceededError(
                f"Cost budget exceeded: {format_cost(self.estimated_cost_usd)} "
                f"> {format_cost(self.max_cost_usd)}"
            )

    def record_call(self, messages: list[Message], response: str) -> BudgetSnapshot:
        """Record token usage for a completion and enforce limits."""
        input_tokens = count_message_tokens(messages)
        output_tokens = estimate_tokens(response)
        self._input_tokens += input_tokens
        self._output_tokens += output_tokens
        self._call_count += 1
        self.check()
        return self.snapshot()

    def record_tokens(self, input_tokens: int, output_tokens: int) -> BudgetSnapshot:
        """Record raw token counts and enforce limits."""
        self._input_tokens += input_tokens
        self._output_tokens += output_tokens
        self._call_count += 1
        self.check()
        return self.snapshot()

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            total_tokens=self.total_tokens,
            estimated_cost_usd=self.estimated_cost_usd,
            remaining_tokens=self.remaining_tokens(),
            limit_tokens=self.max_tokens,
        )

    def reset(self) -> None:
        self._input_tokens = 0
        self._output_tokens = 0
        self._call_count = 0


@dataclass
class BudgetedLLMClient:
    """LLM client wrapper that records token usage against a TokenBudget."""

    client: Any
    budget: TokenBudget = field(default_factory=TokenBudget)

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Any] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        response = self.client.complete(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.budget.record_call(messages, response)
        return response

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Any] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        response = await self.client.acomplete(
            messages,
            tools=tools,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.budget.record_call(messages, response)
        return response
