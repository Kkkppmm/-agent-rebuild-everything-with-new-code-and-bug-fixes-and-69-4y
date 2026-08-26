"""Tests for LLM benchmarking."""

from devai.benchmark import BenchmarkRunner, BenchmarkSample
from devai.core import MockLLMClient


class TestBenchmarkRunner:
    def test_run_mock_client(self):
        runner = BenchmarkRunner(MockLLMClient())
        result = runner.run(iterations=3, name="test-bench")
        assert result.iterations == 3
        assert result.successes == 3
        assert result.failures == 0
        assert result.mean_latency_ms >= 0
        assert "test-bench" in result.summary()

    def test_to_dict(self):
        runner = BenchmarkRunner(MockLLMClient())
        result = runner.run(iterations=2)
        payload = result.to_dict()
        assert payload["iterations"] == 2
        assert len(payload["samples"]) == 2

    def test_sample_fields(self):
        sample = BenchmarkSample(index=0, latency_ms=12.5, output_chars=10, success=True)
        assert sample.error is None
