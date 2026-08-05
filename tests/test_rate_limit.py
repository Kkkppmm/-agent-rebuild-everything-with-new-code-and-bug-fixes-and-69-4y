"""Tests for rate limiting."""

import time

import pytest

from devai.core import Message, MockLLMClient, RateLimitError, RateLimitedLLMClient, RateLimiter


class TestRateLimiter:
    def test_acquire(self):
        limiter = RateLimiter(requests_per_minute=6000, burst=5)
        for _ in range(5):
            limiter.acquire()
        assert limiter.available_tokens < 1.0

    def test_invalid_rate(self):
        with pytest.raises(ValueError):
            RateLimiter(requests_per_minute=0)

    def test_timeout(self):
        limiter = RateLimiter(requests_per_minute=1, burst=1)
        limiter.acquire()
        with pytest.raises(RateLimitError):
            limiter.acquire(timeout=0.05)


class TestRateLimitedLLMClient:
    def test_wraps_client(self):
        inner = MockLLMClient(default_response="ok")
        client = RateLimitedLLMClient(inner, RateLimiter(requests_per_minute=6000))
        result = client.complete([Message.user("hi")])
        assert result == "ok"
        assert len(inner.call_history) == 1

    def test_rate_limits_calls(self):
        inner = MockLLMClient(default_response="ok")
        limiter = RateLimiter(requests_per_minute=60, burst=1)
        client = RateLimitedLLMClient(inner, limiter)
        client.complete([Message.user("a")])
        start = time.monotonic()
        client.complete([Message.user("b")])
        assert time.monotonic() - start >= 0.01
