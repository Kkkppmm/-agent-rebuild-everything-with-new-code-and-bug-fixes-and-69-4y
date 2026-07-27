"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "0.9.0"

    def test_exports(self):
        expected = {
            "Agent",
            "BatchRunner",
            "CodeAssistant",
            "CodeIssue",
            "CodeProject",
            "CodeReviewResult",
            "CoderAgent",
            "DevAIConfig",
            "DevPipeline",
            "LLMClient",
            "MockLLMClient",
            "PerfIssue",
            "PerfReviewResult",
            "SecurityAuditResult",
            "SecurityFinding",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
