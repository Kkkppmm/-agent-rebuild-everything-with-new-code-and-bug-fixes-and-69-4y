"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "1.7.0"

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
            "DevWorkflow",
            "EmbeddingClient",
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
            "SecurityAuditResult",
            "SecurityFinding",
            "WorkflowResult",
            "WorkflowStepResult",
            "get_preset",
            "list_presets",
            "program_schema",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
