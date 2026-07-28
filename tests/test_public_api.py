"""Tests for DevAI public API exports."""

import devai


class TestPublicAPI:
    def test_version(self):
        assert devai.__version__ == "1.3.0"

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
            "DevKit",
            "DevPipeline",
            "DevProgram",
            "EmbeddingClient",
            "LLMClient",
            "MockEmbeddingClient",
            "MockLLMClient",
            "PerfIssue",
            "PerfReviewResult",
            "PluginRegistry",
            "ProgramResult",
            "ProgramTask",
            "SandboxResult",
            "SecurityAuditResult",
            "SecurityFinding",
            "get_preset",
            "list_presets",
            "__version__",
        }
        assert set(devai.__all__) == expected
        for name in expected:
            assert hasattr(devai, name)
