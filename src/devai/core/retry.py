"""Retry utilities for resilient LLM calls."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

from devai.core.exceptions import RateLimitError

T = TypeVar("T")


def with_retries(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    retry_on: tuple[type[Exception], ...] = (RateLimitError,),
) -> T:
    """Execute *fn* with exponential backoff on retryable errors."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except retry_on as exc:
            last_exc = exc
            if attempt == max_retries:
                break
            time.sleep(retry_delay * (2**attempt))
    assert last_exc is not None
    raise last_exc
