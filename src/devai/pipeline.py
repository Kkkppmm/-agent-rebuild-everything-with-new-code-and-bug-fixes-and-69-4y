"""High-level pipelines for common developer AI workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import LLMResponse
from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    REFACTOR,
    SECURITY_REVIEW,
    TEST_GEN,
    PromptTemplate,
)


@dataclass
class PipelineResult:
    """Result from a DevPipeline workflow step."""

    step: str
    response: LLMResponse
    metadata: dict[str, Any] = field(default_factory=dict)


class DevPipeline:
    """Composable developer workflows built on DevAI prompts and clients."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient | None = None,
        *,
        config: DevAIConfig | None = None,
        language: str = "python",
    ) -> None:
        if client is not None:
            self.client = client
        elif config is not None:
            self.client = (
                MockLLMClient() if config.is_mock else LLMClient(config)
            )
        else:
            cfg = DevAIConfig()
            self.client = MockLLMClient() if not cfg.api_key else LLMClient(cfg)
        self.language = language
        self._history: list[PipelineResult] = []

    def review(self, code: str, *, language: str | None = None) -> PipelineResult:
        prompt = PromptTemplate(CODE_REVIEW).format(
            code=code, language=language or self.language
        )
        response = self.client.complete(prompt)
        result = PipelineResult("review", response, {"language": language or self.language})
        self._history.append(result)
        return result

    def explain(self, code: str, *, language: str | None = None) -> PipelineResult:
        prompt = PromptTemplate(EXPLAIN_CODE).format(
            code=code, language=language or self.language
        )
        response = self.client.complete(prompt)
        result = PipelineResult("explain", response)
        self._history.append(result)
        return result

    def debug(self, error: str, code: str = "") -> PipelineResult:
        prompt = PromptTemplate(DEBUG).format(error=error, code=code)
        response = self.client.complete(prompt)
        result = PipelineResult("debug", response, {"error": error})
        self._history.append(result)
        return result

    def commit_message(self, diff: str) -> PipelineResult:
        prompt = PromptTemplate(COMMIT_MESSAGE).format(diff=diff)
        response = self.client.complete(prompt)
        result = PipelineResult("commit_message", response)
        self._history.append(result)
        return result

    def security_review(self, code: str) -> PipelineResult:
        prompt = PromptTemplate(SECURITY_REVIEW).format(code=code)
        response = self.client.complete(prompt)
        result = PipelineResult("security_review", response)
        self._history.append(result)
        return result

    def refactor(self, code: str, goals: str = "readability and maintainability") -> PipelineResult:
        prompt = PromptTemplate(REFACTOR).format(code=code, goals=goals)
        response = self.client.complete(prompt)
        result = PipelineResult("refactor", response, {"goals": goals})
        self._history.append(result)
        return result

    def generate_tests(
        self, code: str, *, framework: str = "pytest"
    ) -> PipelineResult:
        prompt = PromptTemplate(TEST_GEN).format(code=code, framework=framework)
        response = self.client.complete(prompt)
        result = PipelineResult("generate_tests", response, {"framework": framework})
        self._history.append(result)
        return result

    def full_review(self, code: str) -> list[PipelineResult]:
        """Run review, security check, and test generation in sequence."""
        return [
            self.review(code),
            self.security_review(code),
            self.generate_tests(code),
        ]

    @property
    def history(self) -> list[PipelineResult]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()
