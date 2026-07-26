"""Tests for retry utilities."""

import pytest

from devai.core.exceptions import RateLimitError
from devai.core.retry import with_retry


def test_retry_succeeds_first_try():
    result = with_retry(lambda: 42)
    assert result == 42


def test_retry_on_rate_limit():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimitError("rate limited")
        return "ok"

    result = with_retry(flaky, max_retries=3, delay=0.01)
    assert result == "ok"
    assert calls["n"] == 3


def test_retry_exhausted():
    with pytest.raises(RateLimitError):
        with_retry(lambda: (_ for _ in ()).throw(RateLimitError("fail")), max_retries=1, delay=0.01)
