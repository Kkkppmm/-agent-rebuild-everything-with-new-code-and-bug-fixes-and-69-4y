"""High-level code assistant facade."""

from __future__ import annotations

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.prompts import (
  CODE_REVIEW,
  COMMIT_MESSAGE,
  DEBUG,
  DOCSTRING_GEN,
  EXPLAIN,
  GENERATE_TESTS,
  LOG_ANALYSIS,
  README_GEN,
  REFACTOR,
  REGEX_BUILD,
  SECURITY_REVIEW,
  SQL_OPTIMIZE,
  TYPE_HINTS,
)


class CodeAssistant:
  """High-level facade for common developer AI tasks."""

  def __init__(
    self,
    client: LLMClient | MockLLMClient | None = None,
    config: DevAIConfig | None = None,
    language: str = "python",
  ) -> None:
    self.config = config or DevAIConfig.from_env()
    self.client = client or LLMClient(self.config)
    self.language = language

  def _ask(self, prompt: str, system: str | None = None) -> str:
    messages: list[Message] = []
    if system:
      messages.append(Message(role=Role.SYSTEM, content=system))
    elif self.config.system_prompt:
      messages.append(Message(role=Role.SYSTEM, content=self.config.system_prompt))
    messages.append(Message(role=Role.USER, content=prompt))
    return self.client.complete(messages).content

  def review(self, code: str, language: str | None = None) -> str:
    prompt = CODE_REVIEW(language=language or self.language, code=code)
    return self._ask(prompt)

  def explain(self, code: str, language: str | None = None) -> str:
    prompt = EXPLAIN(language=language or self.language, code=code)
    return self._ask(prompt)

  def debug(self, code: str, error: str, language: str | None = None) -> str:
    prompt = DEBUG(language=language or self.language, code=code, error=error)
    return self._ask(prompt)

  def refactor(self, code: str, language: str | None = None) -> str:
    prompt = REFACTOR(language=language or self.language, code=code)
    return self._ask(prompt)

  def generate_tests(self, code: str, language: str | None = None) -> str:
    prompt = GENERATE_TESTS(language=language or self.language, code=code)
    return self._ask(prompt)

  def security_review(self, code: str, language: str | None = None) -> str:
    prompt = SECURITY_REVIEW(language=language or self.language, code=code)
    return self._ask(prompt)

  def commit_message(self, diff: str) -> str:
    return self._ask(COMMIT_MESSAGE(diff=diff))

  def add_type_hints(self, code: str) -> str:
    return self._ask(TYPE_HINTS(code=code))

  def add_docstrings(self, code: str) -> str:
    return self._ask(DOCSTRING_GEN(code=code))

  def optimize_sql(self, query: str, schema: str = "") -> str:
    return self._ask(SQL_OPTIMIZE(query=query, schema=schema))

  def generate_readme(
    self,
    project_name: str,
    description: str,
    features: str = "",
    tech_stack: str = "",
  ) -> str:
    return self._ask(
      README_GEN(
        project_name=project_name,
        description=description,
        features=features,
        tech_stack=tech_stack,
      )
    )

  def build_regex(self, description: str, match_cases: str = "", no_match_cases: str = "") -> str:
    return self._ask(
      REGEX_BUILD(
        description=description,
        match_cases=match_cases,
        no_match_cases=no_match_cases,
      )
    )

  def analyze_logs(self, logs: str) -> str:
    return self._ask(LOG_ANALYSIS(logs=logs))

  def full_review(self, code: str, language: str | None = None) -> dict[str, str]:
    lang = language or self.language
    return {
      "review": self.review(code, lang),
      "security": self.security_review(code, lang),
      "tests": self.generate_tests(code, lang),
    }

  async def areview(self, code: str, language: str | None = None) -> str:
    prompt = CODE_REVIEW(language=language or self.language, code=code)
    messages = [Message(role=Role.USER, content=prompt)]
    return (await self.client.acomplete(messages)).content
