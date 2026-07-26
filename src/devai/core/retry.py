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
    backoff: float = 2.0,
    retry_on: tuple[type[Exception], ...] = (RateLimitError,),
) -> T:
    last_exc: Exception | None = None
    wait = delay
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except retry_on as exc:
            last_exc = exc
            if attempt == max_retries:
                raise
            time.sleep(wait)
            wait *= backoff
    raise last_exc  # type: ignore[misc]
