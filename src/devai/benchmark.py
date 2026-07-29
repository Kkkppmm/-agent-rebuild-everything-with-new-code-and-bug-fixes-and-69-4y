"""Benchmark LLM latency and throughput."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from devai.core.client import LLMClientProtocol, MockLLMClient
from devai.core.models import Message


@dataclass
class BenchmarkResult:
    """Aggregated benchmark metrics."""

    prompt: str
    requests: int
    latencies_ms: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return len(self.latencies_ms)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def mean_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return statistics.mean(self.latencies_ms)

    @property
    def median_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return statistics.median(self.latencies_ms)

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_latencies = sorted(self.latencies_ms)
        index = max(0, int(len(sorted_latencies) * 0.95) - 1)
        return sorted_latencies[index]

    @property
    def throughput_rps(self) -> float:
        total_seconds = sum(self.latencies_ms) / 1000
        if total_seconds <= 0:
            return 0.0
        return self.success_count / total_seconds

    def summarize(self) -> str:
        lines = [
            f"Benchmark: {self.requests} requests",
            f"Prompt: {self.prompt!r}",
            f"Success: {self.success_count}",
            f"Errors: {self.error_count}",
            f"Mean latency: {self.mean_latency_ms:.1f} ms",
            f"Median latency: {self.median_latency_ms:.1f} ms",
            f"P95 latency: {self.p95_latency_ms:.1f} ms",
            f"Throughput: {self.throughput_rps:.2f} req/s",
        ]
        if self.errors:
            lines.append("Sample error: " + self.errors[0])
        return "\n".join(lines)


class BenchmarkRunner:
    """Measure LLM client latency over repeated requests."""

    def __init__(self, client: LLMClientProtocol) -> None:
        self.client = client

    def run(
        self,
        *,
        prompt: str = "Say hello in one word.",
        requests: int = 5,
        max_tokens: int = 16,
    ) -> BenchmarkResult:
        result = BenchmarkResult(prompt=prompt, requests=requests)
        messages = [Message(role="user", content=prompt)]
        for _ in range(requests):
            start = time.perf_counter()
            try:
                self.client.complete(messages, max_tokens=max_tokens)
                result.latencies_ms.append((time.perf_counter() - start) * 1000)
            except Exception as exc:
                result.errors.append(str(exc))
        return result


def benchmark_mock(*, requests: int = 3) -> BenchmarkResult:
    """Run a quick benchmark using the mock client (no API key required)."""
    return BenchmarkRunner(MockLLMClient()).run(requests=requests)
