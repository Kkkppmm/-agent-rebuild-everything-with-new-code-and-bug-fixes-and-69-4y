"""Retry utilities for API calls."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

from devai.core.exceptions import RateLimitError

T = TypeVar("T")


def with_retry(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    delay: float = 1.0,
    retryable: tuple[type[Exception], ...] = (RateLimitError,),
) -> T:
    """Execute *fn* with exponential backoff on retryable errors."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except retryable as exc:
            last_exc = exc
            if attempt < max_retries:
                time.sleep(delay * (2**attempt))
    raise last_exc  # type: ignore[misc]
