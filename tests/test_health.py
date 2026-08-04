"""Tests for health checks and quickstart helpers."""

import pytest

from devai import HealthChecker, HealthResult, MockLLMClient, check_health, quickstart, assistant
from devai.core.config import DevAIConfig


class TestHealthChecker:
    def test_mock_client_healthy(self):
        checker = HealthChecker(client=MockLLMClient())
        result = checker.check()
        assert result.healthy is True
        assert result.provider == "mock"
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_mock_client_healthy_async(self):
        checker = HealthChecker(client=MockLLMClient())
        result = await checker.acheck()
        assert result.healthy is True

    def test_missing_api_key_unhealthy(self):
        config = DevAIConfig(api_key=None)
        checker = HealthChecker(config=config)
        result = checker.check()
        assert result.healthy is False
        assert "API key" in result.message

    def test_no_probe_endpoint_only(self):
        checker = HealthChecker(client=MockLLMClient())
        result = checker.check(probe=False)
        assert result.healthy is True

    def test_to_dict(self):
        result = HealthResult(
            healthy=True,
            provider="mock",
            model="mock-model",
            latency_ms=1.5,
            message="ok",
        )
        data = result.to_dict()
        assert data["healthy"] is True
        assert data["latency_ms"] == 1.5


class TestCheckHealth:
    def test_check_health_mock(self):
        result = check_health(use_mock=True)
        assert result.healthy is True

    def test_check_health_mock_provider(self):
        result = check_health(provider="mock")
        assert result.healthy is True


class TestQuickstart:
    def test_quickstart_mock(self):
        runtime = quickstart(use_mock=True)
        assert runtime.assistant is not None
        review = runtime.review("def foo(): pass")
        assert isinstance(review, str)

    def test_assistant_helper(self):
        a = assistant(use_mock=True)
        assert a.explain("x = 1") is not None
