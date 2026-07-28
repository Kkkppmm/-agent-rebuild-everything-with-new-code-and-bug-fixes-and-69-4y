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
            "ci_gate_passed",
            "extract_annotations",
            "format_actions_annotations",
            "format_actions_summary",
            "format_pr_comment",
            "get_preset",
            "list_presets",
            "write_step_summary",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
