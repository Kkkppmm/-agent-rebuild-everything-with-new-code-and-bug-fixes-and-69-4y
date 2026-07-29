"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "1.9.0"

    def test_exports(self):
        expected = {
            "Agent",
            "BatchRunner",
            "BenchmarkResult",
            "BenchmarkRunner",
            "CIReporter",
            "CodeAssistant",
            "CodeIssue",
            "CodeProject",
            "CodeReviewResult",
            "CodeSandbox",
            "CoderAgent",
            "DevAIConfig",
            "DevApp",
            "DevDoctor",
            "DevKit",
            "DevPipeline",
            "DevProgram",
            "DevRuntime",
            "DevSchedule",
            "DevTrace",
            "DevWorkflow",
            "DoctorCheck",
            "DoctorResult",
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
            "ProgramReport",
            "ProgramResult",
            "ProgramStepPlan",
            "ProgramTask",
            "SandboxResult",
            "ScheduleResult",
            "ScheduledJob",
            "SecurityAuditResult",
            "SecurityFinding",
            "TraceSpan",
            "WorkflowResult",
            "WorkflowStepResult",
            "assistant",
            "benchmark_mock",
            "check_health",
            "config_file_template",
            "cron_matches",
            "find_config_file",
            "get_preset",
            "interpolate",
            "interpolate_dict",
            "list_presets",
            "load_config_file",
            "program_schema",
            "quickstart",
            "run_doctor",
            "validate_cron",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
