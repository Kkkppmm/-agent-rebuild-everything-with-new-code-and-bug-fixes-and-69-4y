"""Tests for retry utility."""

from devai.core.retry import with_retry


def test_retry_success():
    calls = 0

    def fn():
        nonlocal calls
        calls += 1
        return "ok"

    assert with_retry(fn) == "ok"
    assert calls == 1


def test_retry_eventually_succeeds():
    calls = 0

    def fn():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ValueError("fail")
        return "ok"

    assert with_retry(fn, max_retries=3, delay=0.01) == "ok"
    assert calls == 3
