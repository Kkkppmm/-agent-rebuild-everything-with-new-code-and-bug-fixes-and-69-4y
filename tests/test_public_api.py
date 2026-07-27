"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "1.1.0"

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
            "DevKit",
            "DevPipeline",
            "DevProgram",
            "LLMClient",
            "MockLLMClient",
            "PerfIssue",
            "PerfReviewResult",
            "ProgramResult",
            "ProgramTask",
            "SecurityAuditResult",
            "SecurityFinding",
            "get_preset",
            "list_presets",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
