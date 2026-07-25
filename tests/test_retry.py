"""Tests for retry utilities."""

import pytest

from devai.utils.retry import retry_async, retry_sync


def test_retry_sync_succeeds_on_second_attempt():
    attempts = {"count": 0}

    def flaky():
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise ValueError("not yet")
        return "ok"

    assert retry_sync(flaky, max_attempts=3) == "ok"
    assert attempts["count"] == 2


def test_retry_sync_raises_after_max():
    def always_fail():
        raise RuntimeError("fail")

    with pytest.raises(RuntimeError):
        retry_sync(always_fail, max_attempts=2)


@pytest.mark.asyncio
async def test_retry_async_succeeds():
    attempts = {"count": 0}

    async def flaky():
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise ValueError("not yet")
        return "done"

    result = await retry_async(flaky, max_attempts=3)
    assert result == "done"
