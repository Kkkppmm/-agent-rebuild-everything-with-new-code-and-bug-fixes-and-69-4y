"""Tests for benchmarking."""

from devai.benchmark import BenchmarkRunner, benchmark_mock
from devai.core import MockLLMClient


class TestBenchmark:
    def test_benchmark_mock(self):
        result = benchmark_mock(requests=3)
        assert result.success_count == 3
        assert result.mean_latency_ms >= 0

    def test_benchmark_runner(self):
        runner = BenchmarkRunner(MockLLMClient())
        result = runner.run(requests=2, prompt="test")
        assert result.success_count == 2
        summary = result.summarize()
        assert "Mean latency" in summary
