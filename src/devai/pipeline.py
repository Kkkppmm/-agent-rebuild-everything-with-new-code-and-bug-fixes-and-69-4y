"""Composable multi-step developer pipelines."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from devai.assistant import CodeAssistant
from devai.core.config import DevAIConfig


@dataclass
class PipelineStep:
    name: str
    fn: Any


@dataclass
class PipelineResult:
    step: str
    output: str


class DevPipeline:
    """Multi-step pipeline for developer workflows."""

    def __init__(self, config: DevAIConfig | None = None) -> None:
        self.assistant = CodeAssistant(config=config)
        self._steps: list[PipelineStep] = []

    def add_step(self, name: str, fn: Any) -> DevPipeline:
        self._steps.append(PipelineStep(name=name, fn=fn))
        return self

    def run(self, code: str, language: str = "python") -> list[PipelineResult]:
        results: list[PipelineResult] = []
        context: dict[str, Any] = {"code": code, "language": language, "assistant": self.assistant}

        for step in self._steps:
            output = step.fn(**context)
            results.append(PipelineResult(step=step.name, output=output))
            context[step.name] = output

        return results

    @classmethod
    def review_pipeline(cls, config: DevAIConfig | None = None) -> DevPipeline:
        pipeline = cls(config)
        pipeline.add_step("review", lambda assistant, code, language, **_: assistant.review(code, language))
        pipeline.add_step("security", lambda assistant, code, language, **_: assistant.security(code, language))
        pipeline.add_step("tests", lambda assistant, code, language, **_: assistant.generate_tests(code, language))
        return pipeline

    @classmethod
    def debug_pipeline(cls, config: DevAIConfig | None = None) -> DevPipeline:
        pipeline = cls(config)
        pipeline.add_step(
            "explain",
            lambda assistant, code, language, **_: assistant.explain(code, language),
        )
        pipeline.add_step(
            "debug",
            lambda assistant, code, language, error="", **_: assistant.debug(code, error, language),
        )
        return pipeline
