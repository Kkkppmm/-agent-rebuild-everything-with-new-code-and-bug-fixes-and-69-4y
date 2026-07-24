"""Composable developer workflow pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from devai.agents import CoderAgent
from devai.chains import SimpleChain
from devai.core.client import LLMClient, MockLLMClient
from devai.prompts import (
    CODE_REVIEW,
    DEBUG,
    EXPLAIN_CODE,
    REFACTOR,
    SECURITY_REVIEW,
    TEST_GEN,
)


class PipelineStep(str, Enum):
    REVIEW = "review"
    DEBUG = "debug"
    TEST = "test"
    SECURITY = "security"
    REFACTOR = "refactor"
    EXPLAIN = "explain"


@dataclass
class PipelineResult:
    step: str
    output: str


@dataclass
class DevPipeline:
    """Composable pipeline for common developer AI workflows."""

    client: LLMClient | MockLLMClient
    language: str = "python"
    results: list[PipelineResult] = field(default_factory=list)

    def review(self, code: str) -> str:
        chain = SimpleChain(client=self.client, template=CODE_REVIEW)
        output = chain.run(language=self.language, code=code)
        self.results.append(PipelineResult(step="review", output=output))
        return output

    def debug(self, code: str, error: str) -> str:
        chain = SimpleChain(client=self.client, template=DEBUG)
        output = chain.run(error=error, code=code)
        self.results.append(PipelineResult(step="debug", output=output))
        return output

    def generate_tests(self, code: str, framework: str = "pytest") -> str:
        chain = SimpleChain(client=self.client, template=TEST_GEN)
        output = chain.run(language=self.language, code=code, framework=framework)
        self.results.append(PipelineResult(step="test", output=output))
        return output

    def security_review(self, code: str) -> str:
        chain = SimpleChain(client=self.client, template=SECURITY_REVIEW)
        output = chain.run(language=self.language, code=code)
        self.results.append(PipelineResult(step="security", output=output))
        return output

    def refactor(self, code: str, goals: str = "readability and performance") -> str:
        chain = SimpleChain(client=self.client, template=REFACTOR)
        output = chain.run(language=self.language, code=code, goals=goals)
        self.results.append(PipelineResult(step="refactor", output=output))
        return output

    def explain(self, code: str) -> str:
        chain = SimpleChain(client=self.client, template=EXPLAIN_CODE)
        output = chain.run(language=self.language, code=code)
        self.results.append(PipelineResult(step="explain", output=output))
        return output

    def run_agent(self, task: str) -> str:
        agent = CoderAgent(client=self.client)
        output = agent.run(task)
        self.results.append(PipelineResult(step="agent", output=output))
        return output

    def run_all(
        self, code: str, steps: list[PipelineStep] | None = None
    ) -> dict[str, str]:
        """Run multiple pipeline steps on code."""
        steps = steps or [PipelineStep.REVIEW, PipelineStep.SECURITY]
        outputs: dict[str, str] = {}
        for step in steps:
            if step == PipelineStep.REVIEW:
                outputs["review"] = self.review(code)
            elif step == PipelineStep.SECURITY:
                outputs["security"] = self.security_review(code)
            elif step == PipelineStep.EXPLAIN:
                outputs["explain"] = self.explain(code)
            elif step == PipelineStep.TEST:
                outputs["test"] = self.generate_tests(code)
        return outputs

    def summary(self) -> str:
        if not self.results:
            return "No pipeline steps executed."
        lines = [f"=== {r.step.upper()} ===\n{r.output}" for r in self.results]
        return "\n\n".join(lines)
