"""Tests for metrics collection."""

from devai.core import Message, MetricsCollector, MetricsLLMClient, MockLLMClient
from devai.core.exceptions import LLMError


class TestMetricsCollector:
    def test_summary_empty(self):
        metrics = MetricsCollector()
        assert metrics.summary()["total_calls"] == 0

    def test_reset(self):
        metrics = MetricsCollector()
        metrics.calls.append(
            __import__("devai.core.metrics", fromlist=["CallMetric"]).CallMetric(
                duration_seconds=0.1,
                response_length=10,
                message_count=1,
                success=True,
            )
        )
        metrics.reset()
        assert metrics.total_calls == 0


class TestMetricsLLMClient:
    def test_records_success(self):
        inner = MockLLMClient(default_response="hello")
        metrics = MetricsCollector()
        client = MetricsLLMClient(inner, metrics)
        result = client.complete([Message.user("hi")])
        assert result == "hello"
        assert metrics.total_calls == 1
        assert metrics.success_count == 1
        assert metrics.summary()["total_response_chars"] == 5

    def test_records_failure(self):
        inner = MockLLMClient()
        inner.complete = lambda *a, **kw: (_ for _ in ()).throw(LLMError("fail"))  # type: ignore[method-assign]
        metrics = MetricsCollector()
        client = MetricsLLMClient(inner, metrics)
        try:
            client.complete([Message.user("hi")])
        except LLMError:
            pass
        assert metrics.error_count == 1
