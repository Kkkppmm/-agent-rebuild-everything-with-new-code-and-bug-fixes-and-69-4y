"""Composable pipeline for DevAI workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from devai.assistant import CodeAssistant


class PipelineStep(str, Enum):
    REVIEW = "review"
    SECURITY = "security"
    DEBUG = "debug"
    REFACTOR = "refactor"
    TESTS = "tests"
    DOCSTRING = "docstring"
    EXPLAIN = "explain"


@dataclass
class PipelineResult:
    """Result from a pipeline run."""

    step: str
    output: str


@dataclass
class DevPipeline:
    """Composable pipeline for developer workflows."""

    assistant: CodeAssistant
    steps: list[PipelineStep] = field(default_factory=list)

    def add(self, step: PipelineStep | str) -> DevPipeline:
        if isinstance(step, str):
            step = PipelineStep(step)
        self.steps.append(step)
        return self

    def review_then_secure(self) -> DevPipeline:
        return self.add(PipelineStep.REVIEW).add(PipelineStep.SECURITY)

    def full_audit(self) -> DevPipeline:
        return (
            self.add(PipelineStep.REVIEW)
            .add(PipelineStep.SECURITY)
            .add(PipelineStep.DOCSTRING)
            .add(PipelineStep.TESTS)
        )

    def run(self, code: str, **kwargs: Any) -> list[PipelineResult]:
        results: list[PipelineResult] = []
        handlers: dict[PipelineStep, Callable[..., str]] = {
            PipelineStep.REVIEW: lambda c, **kw: self.assistant.review(c),
            PipelineStep.SECURITY: lambda c, **kw: self.assistant.security(c),
            PipelineStep.DEBUG: lambda c, **kw: self.assistant.debug(
                c, kw.get("error", "Unknown error")
            ),
            PipelineStep.REFACTOR: lambda c, **kw: self.assistant.refactor(
                c, kw.get("goals", "improve readability")
            ),
            PipelineStep.TESTS: lambda c, **kw: self.assistant.tests(
                c, kw.get("framework", "pytest")
            ),
            PipelineStep.DOCSTRING: lambda c, **kw: self.assistant.docstring(c),
            PipelineStep.EXPLAIN: lambda c, **kw: self.assistant.explain(c),
        }

        for step in self.steps:
            handler = handlers.get(step)
            if handler:
                output = handler(code, **kwargs)
                results.append(PipelineResult(step=step.value, output=output))

        return results

    def run_and_summarize(self, code: str, **kwargs: Any) -> str:
        results = self.run(code, **kwargs)
        parts = [f"## {r.step.title()}\n\n{r.output}" for r in results]
        return "\n\n---\n\n".join(parts)

    async def arun(self, code: str, **kwargs: Any) -> list[PipelineResult]:
        """Run pipeline steps asynchronously where supported."""
        results: list[PipelineResult] = []
        async_handlers = {
            PipelineStep.REVIEW: lambda c, **kw: self.assistant.areview(c),
        }
        sync_handlers: dict[PipelineStep, Callable[..., str]] = {
            PipelineStep.REVIEW: lambda c, **kw: self.assistant.review(c),
            PipelineStep.SECURITY: lambda c, **kw: self.assistant.security(c),
            PipelineStep.DEBUG: lambda c, **kw: self.assistant.debug(
                c, kw.get("error", "Unknown error")
            ),
            PipelineStep.REFACTOR: lambda c, **kw: self.assistant.refactor(
                c, kw.get("goals", "improve readability")
            ),
            PipelineStep.TESTS: lambda c, **kw: self.assistant.tests(
                c, kw.get("framework", "pytest")
            ),
            PipelineStep.DOCSTRING: lambda c, **kw: self.assistant.docstring(c),
            PipelineStep.EXPLAIN: lambda c, **kw: self.assistant.explain(c),
        }

        for step in self.steps:
            if step in async_handlers:
                output = await async_handlers[step](code, **kwargs)
            else:
                handler = sync_handlers.get(step)
                if handler:
                    output = handler(code, **kwargs)
                else:
                    continue
            results.append(PipelineResult(step=step.value, output=output))

        return results
