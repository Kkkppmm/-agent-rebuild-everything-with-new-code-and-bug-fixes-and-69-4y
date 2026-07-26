"""Tests for DevAI retry utilities."""

import pytest

from devai.core.exceptions import RetryExhaustedError
from devai.core.retry import with_retry


def test_with_retry_success():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        return "ok"

    assert with_retry(fn, max_retries=3) == "ok"
    assert calls["n"] == 1


def test_with_retry_eventual_success():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("not yet")
        return "ok"

    assert with_retry(fn, max_retries=5, delay=0.01) == "ok"
    assert calls["n"] == 3


def test_with_retry_exhausted():
    def fn():
        raise RuntimeError("always fails")

    with pytest.raises(RetryExhaustedError):
        with_retry(fn, max_retries=2, delay=0.01)
