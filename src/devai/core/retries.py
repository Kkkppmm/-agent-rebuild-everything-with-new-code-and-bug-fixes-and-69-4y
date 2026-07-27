"""Retry utilities for API calls."""

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
  base_delay: float = 1.0,
  retry_on: tuple[type[Exception], ...] = (RateLimitError,),
) -> T:
  last_exc: Exception | None = None
  for attempt in range(max_retries + 1):
    try:
      return fn()
    except retry_on as exc:
      last_exc = exc
      if attempt < max_retries:
        time.sleep(base_delay * (2**attempt))
  raise last_exc  # type: ignore[misc]
