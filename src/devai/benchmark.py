"""Benchmark LLM clients for latency and throughput."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from devai.core.client import LLMClientProtocol, MockLLMClient
from devai.core.models import Message


@dataclass
class BenchmarkSample:
    """Timing for a single benchmark request."""

    index: int
    latency_ms: float
    output_chars: int
    success: bool
    error: str | None = None


@dataclass
class BenchmarkResult:
    """Aggregated benchmark statistics."""

    name: str
    iterations: int
    samples: list[BenchmarkSample] = field(default_factory=list)

    @property
    def successes(self) -> int:
        return sum(1 for sample in self.samples if sample.success)

    @property
    def failures(self) -> int:
        return self.iterations - self.successes

    @property
    def latencies_ms(self) -> list[float]:
        return [sample.latency_ms for sample in self.samples if sample.success]

    @property
    def mean_latency_ms(self) -> float:
        values = self.latencies_ms
        return statistics.mean(values) if values else 0.0

    @property
    def median_latency_ms(self) -> float:
        values = self.latencies_ms
        return statistics.median(values) if values else 0.0

    @property
    def p95_latency_ms(self) -> float:
        values = sorted(self.latencies_ms)
        if not values:
            return 0.0
        index = max(0, int(len(values) * 0.95) - 1)
        return values[index]

    @property
    def throughput_rps(self) -> float:
        total_seconds = sum(sample.latency_ms for sample in self.samples if sample.success) / 1000
        if total_seconds <= 0:
            return 0.0
        return self.successes / total_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "successes": self.successes,
            "failures": self.failures,
            "mean_latency_ms": round(self.mean_latency_ms, 2),
            "median_latency_ms": round(self.median_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "throughput_rps": round(self.throughput_rps, 2),
            "samples": [
                {
                    "index": sample.index,
                    "latency_ms": round(sample.latency_ms, 2),
                    "output_chars": sample.output_chars,
                    "success": sample.success,
                    "error": sample.error,
                }
                for sample in self.samples
            ],
        }

    def summary(self) -> str:
        return (
            f"{self.name}: {self.successes}/{self.iterations} ok, "
            f"mean={self.mean_latency_ms:.1f}ms, "
            f"p95={self.p95_latency_ms:.1f}ms, "
            f"throughput={self.throughput_rps:.2f} req/s"
        )


class BenchmarkRunner:
    """Run repeatable latency benchmarks against an LLM client."""

    def __init__(
        self,
        client: LLMClientProtocol | None = None,
        *,
        prompt: str = "Reply with exactly: benchmark-ok",
        system: str = "You are a benchmark harness. Keep responses short.",
    ) -> None:
        self.client = client or MockLLMClient()
        self.prompt = prompt
        self.system = system

    def run(
        self,
        *,
        iterations: int = 5,
        name: str = "llm-benchmark",
        temperature: float | None = 0.0,
    ) -> BenchmarkResult:
        if iterations < 1:
            raise ValueError("iterations must be at least 1")

        result = BenchmarkResult(name=name, iterations=iterations)
        messages = [
            Message(role="system", content=self.system),
            Message(role="user", content=self.prompt),
        ]

        for index in range(iterations):
            started = time.perf_counter()
            try:
                output = self.client.complete(messages, temperature=temperature)
                elapsed_ms = (time.perf_counter() - started) * 1000
                result.samples.append(
                    BenchmarkSample(
                        index=index,
                        latency_ms=elapsed_ms,
                        output_chars=len(output),
                        success=True,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - benchmark should capture failures
                elapsed_ms = (time.perf_counter() - started) * 1000
                result.samples.append(
                    BenchmarkSample(
                        index=index,
                        latency_ms=elapsed_ms,
                        output_chars=0,
                        success=False,
                        error=str(exc),
                    )
                )
        return result
