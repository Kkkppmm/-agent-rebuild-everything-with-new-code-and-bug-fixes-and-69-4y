"""Metrics collection for LLM calls."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Any

from devai.core.models import Message, Tool


@dataclass
class CallMetric:
    """Metrics from a single LLM call."""

    duration_seconds: float
    response_length: int
    message_count: int
    success: bool
    error: str | None = None


@dataclass
class MetricsCollector:
    """Collect latency, throughput, and error metrics for LLM calls."""

    calls: list[CallMetric] = field(default_factory=list)

    @property
    def total_calls(self) -> int:
        return len(self.calls)

    @property
    def success_count(self) -> int:
        return sum(1 for c in self.calls if c.success)

    @property
    def error_count(self) -> int:
        return sum(1 for c in self.calls if not c.success)

    @property
    def total_duration(self) -> float:
        return sum(c.duration_seconds for c in self.calls)

    @property
    def avg_duration(self) -> float:
        if not self.calls:
            return 0.0
        return self.total_duration / len(self.calls)

    @property
    def total_response_chars(self) -> int:
        return sum(c.response_length for c in self.calls)

    def summary(self) -> dict[str, float | int]:
        """Return a summary dict of collected metrics."""
        return {
            "total_calls": self.total_calls,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "avg_duration_seconds": round(self.avg_duration, 4),
            "total_duration_seconds": round(self.total_duration, 4),
            "total_response_chars": self.total_response_chars,
        }

    def reset(self) -> None:
        """Clear all collected metrics."""
        self.calls.clear()


class MetricsLLMClient:
    """LLM client wrapper that records call metrics."""

    def __init__(self, client: Any, metrics: MetricsCollector | None = None) -> None:
        self.client = client
        self.metrics = metrics or MetricsCollector()

    def _record(
        self,
        start: float,
        messages: list[Message],
        response: str = "",
        *,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        self.metrics.calls.append(
            CallMetric(
                duration_seconds=time.monotonic() - start,
                response_length=len(response),
                message_count=len(messages),
                success=success,
                error=error,
            )
        )

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        start = time.monotonic()
        try:
            response = self.client.complete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self._record(start, messages, response)
            return response
        except Exception as e:
            self._record(start, messages, success=False, error=str(e))
            raise

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        start = time.monotonic()
        chunks: list[str] = []
        try:
            for chunk in self.client.stream(
                messages, temperature=temperature, max_tokens=max_tokens
            ):
                chunks.append(chunk)
                yield chunk
            self._record(start, messages, "".join(chunks))
        except Exception as e:
            self._record(start, messages, success=False, error=str(e))
            raise

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        start = time.monotonic()
        try:
            response = await self.client.acomplete(
                messages,
                tools=tools,
                json_mode=json_mode,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            self._record(start, messages, response)
            return response
        except Exception as e:
            self._record(start, messages, success=False, error=str(e))
            raise

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        start = time.monotonic()
        chunks: list[str] = []
        try:
            async for chunk in self.client.astream(
                messages, temperature=temperature, max_tokens=max_tokens
            ):
                chunks.append(chunk)
                yield chunk
            self._record(start, messages, "".join(chunks))
        except Exception as e:
            self._record(start, messages, success=False, error=str(e))
            raise
