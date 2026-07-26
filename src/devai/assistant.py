"""High-level CodeAssistant API for developer AI workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.pipeline import DevPipeline, PipelineStep


class CodeAssistant:
    """Simple, developer-friendly API for common AI coding tasks.

    Example::

        from devai import CodeAssistant

        assistant = CodeAssistant.from_env()
        print(assistant.review("def foo(): pass"))

        # Or with a mock client for testing
        assistant = CodeAssistant.mock()
        print(assistant.explain("x = [i**2 for i in range(10)]"))
    """

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        language: str = "python",
    ) -> None:
        self._pipeline = DevPipeline(client=client, language=language)

    @classmethod
    def from_config(cls, config: DevAIConfig | None = None, **kwargs: Any) -> CodeAssistant:
        """Create an assistant from DevAIConfig or keyword arguments."""
        config = config or DevAIConfig(**kwargs)
        if config.is_mock:
            return cls(client=MockLLMClient())
        return cls(client=LLMClient(config))

    @classmethod
    def from_env(cls, **kwargs: Any) -> CodeAssistant:
        """Create an assistant using environment variables (DEVAI_*)."""
        return cls.from_config(DevAIConfig(**kwargs))

    @classmethod
    def mock(cls, responses: list[str] | None = None, **kwargs: Any) -> CodeAssistant:
        """Create an assistant with a mock client (no API key required)."""
        return cls(client=MockLLMClient(responses=responses, **kwargs))

    def review(self, code: str) -> str:
        """Review code for bugs, style, and improvements."""
        return self._pipeline.review(code)

    def review_file(self, path: str | Path) -> str:
        """Review a source file."""
        code = Path(path).read_text(encoding="utf-8")
        return self.review(code)

    def explain(self, code: str) -> str:
        """Explain what code does."""
        return self._pipeline.explain(code)

    def debug(self, code: str, error: str) -> str:
        """Debug an error given code context."""
        return self._pipeline.debug(code, error)

    def refactor(self, code: str, goals: str = "readability and performance") -> str:
        """Suggest refactoring improvements."""
        return self._pipeline.refactor(code, goals=goals)

    def security_review(self, code: str) -> str:
        """Run a security-focused code review."""
        return self._pipeline.security_review(code)

    def generate_tests(self, code: str, framework: str = "pytest") -> str:
        """Generate unit tests for code."""
        return self._pipeline.generate_tests(code, framework=framework)

    def run_agent(self, task: str) -> str:
        """Run an autonomous coding agent on a task."""
        return self._pipeline.run_agent(task)

    def full_review(
        self,
        code: str,
        *,
        include_tests: bool = False,
    ) -> dict[str, str]:
        """Run review, security check, and optionally test generation."""
        steps = [PipelineStep.REVIEW, PipelineStep.SECURITY]
        if include_tests:
            steps.append(PipelineStep.TEST)
        return self._pipeline.run_all(code, steps=steps)

    def summary(self) -> str:
        """Return a summary of all steps run in this session."""
        return self._pipeline.summary()
