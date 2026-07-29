"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "2.0.0"

    def test_exports(self):
        expected = {
            "Agent",
            "BatchRunner",
            "CIReporter",
            "CodeAssistant",
            "CodeIssue",
            "CodeProject",
            "CodeReviewResult",
            "CodeSandbox",
            "CoderAgent",
            "DevAIConfig",
            "DevApp",
            "DevKit",
            "DevPipeline",
            "DevProgram",
            "DevRuntime",
            "DevSchedule",
            "DevTrace",
            "DevWorkflow",
            "EmbeddingClient",
            "GitContext",
            "HealthChecker",
            "HealthResult",
            "LLMClient",
            "MockEmbeddingClient",
            "MockLLMClient",
            "PerfIssue",
            "PerfReviewResult",
            "PluginRegistry",
            "ProgramResult",
            "ProgramStepPlan",
            "ProgramTask",
            "SandboxResult",
            "ScheduleResult",
            "ScheduledJob",
            "SecurityAuditResult",
            "SecurityFinding",
            "TraceEvent",
            "WorkflowResult",
            "WorkflowStepResult",
            "assistant",
            "check_health",
            "cron_matches",
            "get_preset",
            "interpolate",
            "interpolate_context",
            "list_presets",
            "program_schema",
            "quickstart",
            "validate_cron",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
