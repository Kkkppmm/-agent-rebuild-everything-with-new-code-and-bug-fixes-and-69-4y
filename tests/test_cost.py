"""Tests for token and cost estimation."""

from devai.utils import estimate_cost, estimate_tokens


class TestCostEstimation:
    def test_estimate_tokens(self):
        assert estimate_tokens("hello world") >= 1
        assert estimate_tokens("") == 1

    def test_estimate_cost(self):
        result = estimate_cost("a" * 400, "b" * 200, model="gpt-4o-mini")
        assert result["input_tokens"] == 100
        assert result["output_tokens"] == 50
        assert result["total_tokens"] == 150
        assert result["estimated_cost_usd"] > 0
        assert result["model"] == "gpt-4o-mini"

    def test_estimate_cost_unknown_model(self):
        result = estimate_cost("test", model="unknown-model")
        assert result["model"] == "unknown-model"
        assert result["estimated_cost_usd"] >= 0
