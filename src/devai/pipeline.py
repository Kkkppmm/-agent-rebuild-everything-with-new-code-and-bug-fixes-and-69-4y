"""Composable pipelines for developer workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from devai.assistant import CodeAssistant


@dataclass
class PipelineStep:
    name: str
    fn: Callable[[str, dict[str, Any]], str]


@dataclass
class PipelineResult:
    outputs: dict[str, str] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)


class DevPipeline:
    """Chain multiple assistant operations into a workflow."""

    def __init__(self, assistant: CodeAssistant) -> None:
        self.assistant = assistant
        self._steps: list[PipelineStep] = []

    def add_step(self, name: str, fn: Callable[[str, dict[str, Any]], str]) -> DevPipeline:
        self._steps.append(PipelineStep(name=name, fn=fn))
        return self

    def review_then_test(self) -> DevPipeline:
        return (
            self.add_step("review", lambda code, ctx: self.assistant.review(code))
            .add_step("tests", lambda code, ctx: self.assistant.generate_tests(code))
        )

    def debug_then_fix(self, error: str) -> DevPipeline:
        self._error = error
        return self.add_step(
            "debug",
            lambda code, ctx: self.assistant.debug(code, error),
        ).add_step(
            "refactor",
            lambda code, ctx: self.assistant.refactor(ctx.get("debug", code)),
        )

    def run(self, code: str, **context: Any) -> PipelineResult:
        result = PipelineResult(context=dict(context))
        current_code = code
        for step in self._steps:
            output = step.fn(current_code, result.context)
            result.outputs[step.name] = output
            result.context[step.name] = output
        return result
