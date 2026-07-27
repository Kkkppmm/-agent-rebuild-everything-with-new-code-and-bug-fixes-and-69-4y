"""High-level code assistant facade."""

from __future__ import annotations

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG_CODE,
    EXPLAIN_CODE,
    GENERATE_TESTS,
    REFACTOR_CODE,
    SECURITY_REVIEW,
)
from devai.utils import truncate_to_tokens


class CodeAssistant:
    """Developer-focused AI assistant for common coding tasks."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient | None = None,
        config: DevAIConfig | None = None,
        language: str = "python",
        max_input_tokens: int = 8000,
    ) -> None:
        if client is None:
            config = config or DevAIConfig()
            client = LLMClient(config)
        self.client = client
        self.language = language
        self.max_input_tokens = max_input_tokens

    def _ask(self, prompt: str) -> str:
        messages = [Message(role=Role.USER, content=prompt)]
        return self.client.complete(messages).content

    def _prepare_code(self, code: str) -> str:
        return truncate_to_tokens(code, self.max_input_tokens)

    def review(self, code: str, language: str | None = None) -> str:
        """Review code for bugs, style, and improvements."""
        prompt = CODE_REVIEW.format(
            language=language or self.language,
            code=self._prepare_code(code),
        )
        return self._ask(prompt)

    def explain(self, code: str, language: str | None = None) -> str:
        """Explain what code does."""
        prompt = EXPLAIN_CODE.format(
            language=language or self.language,
            code=self._prepare_code(code),
        )
        return self._ask(prompt)

    def debug(self, code: str, error: str, language: str | None = None) -> str:
        """Debug code given an error message."""
        prompt = DEBUG_CODE.format(
            language=language or self.language,
            code=self._prepare_code(code),
            error=error,
        )
        return self._ask(prompt)

    def refactor(self, code: str, goals: str = "readability and maintainability", language: str | None = None) -> str:
        """Suggest refactoring for code."""
        prompt = REFACTOR_CODE.format(
            language=language or self.language,
            code=self._prepare_code(code),
            goals=goals,
        )
        return self._ask(prompt)

    def security_review(self, code: str, language: str | None = None) -> str:
        """Perform a security audit on code."""
        prompt = SECURITY_REVIEW.format(
            language=language or self.language,
            code=self._prepare_code(code),
        )
        return self._ask(prompt)

    def generate_tests(self, code: str, framework: str = "pytest", language: str | None = None) -> str:
        """Generate unit tests for code."""
        prompt = GENERATE_TESTS.format(
            language=language or self.language,
            code=self._prepare_code(code),
            framework=framework,
        )
        return self._ask(prompt)

    def commit_message(self, diff: str) -> str:
        """Generate a commit message from a diff."""
        prompt = COMMIT_MESSAGE.format(diff=truncate_to_tokens(diff, self.max_input_tokens))
        return self._ask(prompt)

    def full_review(self, code: str, language: str | None = None) -> dict[str, str]:
        """Run review, security audit, and test generation."""
        lang = language or self.language
        prepared = self._prepare_code(code)
        return {
            "review": self.review(prepared, lang),
            "security": self.security_review(prepared, lang),
            "tests": self.generate_tests(prepared, language=lang),
        }

    def ask(self, question: str) -> str:
        """Ask a general coding question."""
        return self._ask(question)
