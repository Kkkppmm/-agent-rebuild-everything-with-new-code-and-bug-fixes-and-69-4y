"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "1.2.0"

    def test_exports(self):
        expected = {
            "Agent",
            "BatchRunner",
            "CIAnnotation",
            "CIReport",
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
            "merge_reports",
            "report_from_performance_review",
            "report_from_program_results",
            "report_from_security_audit",
            "report_from_structured_review",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
