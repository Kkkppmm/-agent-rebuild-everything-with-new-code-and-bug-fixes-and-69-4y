"""Tests for token and cost utilities."""

from devai.core.models import Message
from devai.utils import count_message_tokens, estimate_cost, estimate_message_cost, format_cost


class TestTokenUtils:
    def test_count_message_tokens(self):
        messages = [
            Message.system("You are helpful"),
            Message.user("Hello world"),
        ]
        assert count_message_tokens(messages) > 0

    def test_estimate_cost(self):
        cost = estimate_cost(1000, 500, model="gpt-4o-mini")
        assert cost > 0
        assert cost < 1.0

    def test_estimate_message_cost(self):
        messages = [Message.user("Write a function")]
        cost = estimate_message_cost(messages, "def foo(): pass", model="gpt-4o-mini")
        assert cost > 0

    def test_format_cost(self):
        assert format_cost(0.001234).startswith("$")
        assert format_cost(1.5) == "$1.5000"

    def test_unknown_model_uses_fallback(self):
        cost = estimate_cost(1000, 1000, model="unknown-model-v9")
        assert cost > 0
