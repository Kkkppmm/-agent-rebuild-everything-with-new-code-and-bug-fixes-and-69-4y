"""Tests for token budget tracking."""

import pytest

from devai.core.exceptions import BudgetExceededError
from devai.core.models import Message
from devai.utils.budget import BudgetedLLMClient, TokenBudget


class TestTokenBudget:
    def test_records_tokens(self):
        budget = TokenBudget(max_tokens=10000)
        messages = [Message.user("hello world")]
        snapshot = budget.record_call(messages, "response text")

        assert snapshot.total_tokens > 0
        assert budget.call_count == 1

    def test_enforces_token_limit(self):
        budget = TokenBudget(max_tokens=5)
        with pytest.raises(BudgetExceededError):
            budget.record_tokens(10, 10)

    def test_enforces_cost_limit(self):
        budget = TokenBudget(max_cost_usd=0.000001)
        with pytest.raises(BudgetExceededError):
            budget.record_tokens(10000, 10000)

    def test_remaining_tokens(self):
        budget = TokenBudget(max_tokens=100)
        budget.record_tokens(30, 20)
        assert budget.remaining_tokens() == 50

    def test_reset(self):
        budget = TokenBudget()
        budget.record_tokens(100, 50)
        budget.reset()
        assert budget.total_tokens == 0
        assert budget.call_count == 0

    def test_snapshot_to_dict(self):
        budget = TokenBudget(max_tokens=500)
        budget.record_tokens(10, 5)
        data = budget.snapshot().to_dict()
        assert data["total_tokens"] == 15
        assert data["limit_tokens"] == 500


class TestBudgetedLLMClient:
    def test_records_on_complete(self):
        from devai.core import MockLLMClient

        budget = TokenBudget()
        client = BudgetedLLMClient(MockLLMClient(), budget=budget)
        client.complete([Message.user("test")])

        assert budget.call_count == 1
        assert budget.total_tokens > 0
