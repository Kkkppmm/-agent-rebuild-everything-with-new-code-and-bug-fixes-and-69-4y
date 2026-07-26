"""Retry utilities for DevAI."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

from devai.core.exceptions import RetryExhaustedError

T = TypeVar("T")


def with_retry(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    retryable: Callable[[Exception], bool] | None = None,
) -> T:
    """Execute fn with exponential backoff retries."""
    last_exc: Exception | None = None
    wait = delay

    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt == max_retries:
                break
            if retryable and not retryable(exc):
                raise
            time.sleep(wait)
            wait *= backoff

    raise RetryExhaustedError(
        f"Failed after {max_retries + 1} attempts: {last_exc}"
    ) from last_exc
