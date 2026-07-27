"""Composable multi-step developer workflows."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from devai.assistant import CodeAssistant


class LLMProtocol(Protocol):
  def complete(self, messages: list[Any], **kwargs: Any) -> Any: ...


@dataclass
class PipelineStep:
  name: str
  fn: Callable[..., str]
  kwargs: dict[str, Any] = field(default_factory=dict)


class DevPipeline:
  """Compose multi-step review/debug/test workflows."""

  def __init__(self, assistant: CodeAssistant) -> None:
    self.assistant = assistant
    self.steps: list[PipelineStep] = []

  def add_step(self, name: str, fn: Callable[..., str], **kwargs: Any) -> DevPipeline:
    self.steps.append(PipelineStep(name=name, fn=fn, kwargs=kwargs))
    return self

  def review_pipeline(self, code: str) -> dict[str, str]:
    """Standard review → security → tests pipeline."""
    return {
      "review": self.assistant.review(code),
      "security": self.assistant.security_audit(code),
      "tests": self.assistant.generate_tests(code),
    }

  def debug_pipeline(self, error: str, code: str) -> dict[str, str]:
    """Debug → refactor pipeline."""
    debug_result = self.assistant.debug(error, code)
    return {
      "debug": debug_result,
      "refactor": self.assistant.refactor(code, goal="fix the reported issue and improve robustness"),
    }

  def run(self, **shared_kwargs: Any) -> dict[str, str]:
    results: dict[str, str] = {}
    for step in self.steps:
      results[step.name] = step.fn(**{**shared_kwargs, **step.kwargs})
    return results

  @classmethod
  def from_assistant(cls, assistant: CodeAssistant) -> DevPipeline:
    pipeline = cls(assistant)
    pipeline.add_step("review", assistant.review)
    pipeline.add_step("security", assistant.security_audit)
    pipeline.add_step("tests", assistant.generate_tests)
    return pipeline
