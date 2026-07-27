"""High-level CodeAssistant facade for developer tasks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol

from devai.core.models import Message, Role
from devai.prompts import (
  CODE_REVIEW,
  COMMIT_MESSAGE,
  DEBUG,
  DOCSTRING_GEN,
  EXPLAIN,
  REFACTOR,
  SECURITY_REVIEW,
  TEST_GENERATION,
)
from devai.utils import format_file_tree, truncate_to_tokens


class LLMProtocol(Protocol):
  def complete(self, messages: list[Message], **kwargs: Any) -> Any: ...
  def stream(self, messages: list[Message], **kwargs: Any) -> Any: ...


class CodeAssistant:
  """High-level facade for common developer AI tasks."""

  def __init__(self, client: LLMProtocol, language: str = "python") -> None:
    self.client = client
    self.language = language

  def _ask(self, prompt: str, system: str = "You are an expert software engineer.", **kwargs: Any) -> str:
    messages = [
      Message(role=Role.SYSTEM, content=system),
      Message(role=Role.USER, content=prompt),
    ]
    result = self.client.complete(messages, **kwargs)
    return result.content if hasattr(result, "content") else str(result)

  def review(self, code: str, language: str | None = None) -> str:
    prompt = CODE_REVIEW.format(code=code, language=language or self.language)
    return self._ask(prompt)

  def explain(self, code: str, language: str | None = None) -> str:
    prompt = EXPLAIN.format(code=code, language=language or self.language)
    return self._ask(prompt)

  def debug(self, error: str, code: str, language: str | None = None) -> str:
    prompt = DEBUG.format(error=error, code=code, language=language or self.language)
    return self._ask(prompt)

  def refactor(self, code: str, goal: str = "improve readability and maintainability", language: str | None = None) -> str:
    prompt = REFACTOR.format(code=code, goal=goal, language=language or self.language)
    return self._ask(prompt)

  def security_audit(self, code: str, language: str | None = None) -> str:
    prompt = SECURITY_REVIEW.format(code=code, language=language or self.language)
    return self._ask(prompt)

  def generate_tests(self, code: str, framework: str = "pytest", language: str | None = None) -> str:
    prompt = TEST_GENERATION.format(code=code, framework=framework, language=language or self.language)
    return self._ask(prompt)

  def generate_docstrings(self, code: str, style: str = "Google", language: str | None = None) -> str:
    prompt = DOCSTRING_GEN.format(code=code, style=style, language=language or self.language)
    return self._ask(prompt)

  def commit_message(self, diff: str) -> str:
    prompt = COMMIT_MESSAGE.format(diff=truncate_to_tokens(diff, 3000))
    return self._ask(prompt)

  def review_file(self, path: str) -> str:
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    ext = Path(path).suffix.lstrip(".") or self.language
    return self.review(code, language=ext)

  def review_directory(self, directory: str, extensions: tuple[str, ...] = (".py", ".js", ".ts", ".go", ".rs")) -> str:
    from devai.prompts import DIRECTORY_REVIEW
    paths = []
    for root, _, files in os.walk(directory):
      for f in files:
        if f.endswith(extensions):
          paths.append(os.path.join(root, f))
    file_summaries = []
    for p in paths[:20]:
      try:
        content = Path(p).read_text(encoding="utf-8", errors="replace")
        file_summaries.append(f"### {p}\n```\n{truncate_to_tokens(content, 500)}\n```")
      except OSError:
        continue
    prompt = DIRECTORY_REVIEW.format(
      directory=directory,
      files=format_file_tree(paths, directory) + "\n\n" + "\n\n".join(file_summaries),
    )
    return self._ask(prompt)

  def full_review(self, path: str) -> dict[str, str]:
    """Run review, security audit, and test suggestions on a file."""
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    ext = Path(path).suffix.lstrip(".") or self.language
    return {
      "review": self.review(code, language=ext),
      "security": self.security_audit(code, language=ext),
      "tests": self.generate_tests(code, language=ext),
    }
