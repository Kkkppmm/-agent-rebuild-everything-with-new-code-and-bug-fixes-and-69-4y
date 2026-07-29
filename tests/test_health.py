"""Tests for health checks."""

from devai.health import HealthChecker, check_health
from devai.core import DevAIConfig, MockLLMClient


class TestHealthChecker:
    def test_mock_health(self):
        result = check_health(use_mock=True)
        assert result.healthy
        assert result.provider == "mock"
        assert result.latency_ms is not None

    def test_checker_with_client(self):
        config = DevAIConfig(api_key="mock", model="test")
        checker = HealthChecker(client=MockLLMClient(), config=config)
        result = checker.check()
        assert result.healthy
        assert result.model == "test"

    def test_format_report(self):
        result = check_health(use_mock=True)
        report = result.format_report()
        assert "healthy" in report.lower()
        assert "mock" in report
