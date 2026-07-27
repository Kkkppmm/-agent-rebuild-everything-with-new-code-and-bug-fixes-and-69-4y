"""High-level code assistant facade."""

from __future__ import annotations

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts.dev_prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN,
    REFACTOR,
    SECURITY_REVIEW,
    TEST_GENERATION,
)


class CodeAssistant:
    """Developer-focused AI assistant for common coding tasks."""

    def __init__(
        self,
        config: DevAIConfig | None = None,
        client: LLMClient | None = None,
    ) -> None:
        self.config = config or DevAIConfig.from_env()
        if client is not None:
            self.client = client
        elif self.config.api_key == "mock-key":
            self.client = MockLLMClient(self.config)
        else:
            self.client = LLMClient(self.config)

    def review(self, code: str, language: str = "python") -> str:
        prompt = CODE_REVIEW(code=code, language=language)
        return self._complete(prompt)

    def explain(self, code: str, language: str = "python") -> str:
        prompt = EXPLAIN(code=code, language=language)
        return self._complete(prompt)

    def debug(
        self,
        code: str,
        error: str,
        language: str = "python",
        context: str = "",
    ) -> str:
        prompt = DEBUG(code=code, error=error, language=language, context=context)
        return self._complete(prompt)

    def refactor(
        self,
        code: str,
        language: str = "python",
        goals: str = "readability and maintainability",
    ) -> str:
        prompt = REFACTOR(code=code, language=language, goals=goals)
        return self._complete(prompt)

    def security(self, code: str, language: str = "python") -> str:
        prompt = SECURITY_REVIEW(code=code, language=language)
        return self._complete(prompt)

    def generate_tests(
        self,
        code: str,
        language: str = "python",
        framework: str = "pytest",
    ) -> str:
        prompt = TEST_GENERATION(code=code, language=language, framework=framework)
        return self._complete(prompt)

    def commit_message(self, diff: str) -> str:
        prompt = COMMIT_MESSAGE(diff=diff)
        return self._complete(prompt)

    def full_review(self, code: str, language: str = "python") -> dict[str, str]:
        return {
            "review": self.review(code, language),
            "security": self.security(code, language),
            "tests": self.generate_tests(code, language),
        }

    def chat(self, message: str, system: str = "You are a helpful programming assistant.") -> str:
        messages = [Message.system(system), Message.user(message)]
        response = self.client.complete(messages)
        return response.content or ""

    def _complete(self, prompt: str) -> str:
        messages = [
            Message.system("You are an expert software developer and code reviewer."),
            Message.user(prompt),
        ]
        response = self.client.complete(messages)
        return response.content or ""
