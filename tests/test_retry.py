"""Tests for retry utilities."""

from devai.core.exceptions import RateLimitError
from devai.core.retry import with_retry


def test_with_retry_success():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        return "ok"

    assert with_retry(fn) == "ok"
    assert calls["n"] == 1


def test_with_retry_eventual_success():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimitError("rate limited")
        return "ok"

    assert with_retry(fn, max_retries=3, delay=0.01) == "ok"
    assert calls["n"] == 3
