"""Composable developer workflow pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field

from devai.assistant import CodeAssistant
from devai.core.client import LLMClient, MockLLMClient


@dataclass
class PipelineStep:
  name: str
  action: str  # review, debug, security, tests, explain, refactor


@dataclass
class PipelineResult:
  step: str
  output: str


@dataclass
class DevPipeline:
  """Composable pipeline for multi-step developer workflows."""

  assistant: CodeAssistant
  steps: list[PipelineStep] = field(default_factory=list)

  @classmethod
  def create(
    cls,
    client: LLMClient | MockLLMClient | None = None,
    steps: list[PipelineStep] | None = None,
  ) -> DevPipeline:
    assistant = CodeAssistant(client=client)
    return cls(assistant=assistant, steps=steps or [])

  def add_step(self, name: str, action: str) -> DevPipeline:
    self.steps.append(PipelineStep(name=name, action=action))
    return self

  def run(self, code: str, **kwargs: str) -> list[PipelineResult]:
    results: list[PipelineResult] = []
    for step in self.steps:
      output = self._execute_step(step, code, **kwargs)
      results.append(PipelineResult(step=step.name, output=output))
    return results

  def _execute_step(self, step: PipelineStep, code: str, **kwargs: str) -> str:
    actions = {
      "review": lambda: self.assistant.review(code),
      "debug": lambda: self.assistant.debug(code, kwargs.get("error", "")),
      "security": lambda: self.assistant.security_review(code),
      "tests": lambda: self.assistant.generate_tests(code),
      "explain": lambda: self.assistant.explain(code),
      "refactor": lambda: self.assistant.refactor(code),
    }
    fn = actions.get(step.action)
    if not fn:
      return f"Unknown action: {step.action}"
    return fn()

  def review_pipeline(self, code: str) -> dict[str, str]:
    """Run a standard review pipeline: review + security + tests."""
    return self.assistant.full_review(code)
