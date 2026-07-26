"""Chain implementations for composing LLM calls."""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.prompts.templates import PromptTemplate

T = TypeVar("T", bound=BaseModel)


class Chain:
    """A single-step LLM chain with a prompt template."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        template: str | PromptTemplate,
        output_key: str = "result",
    ):
        self.client = client
        self.template = template if isinstance(template, PromptTemplate) else PromptTemplate(template)
        self.output_key = output_key

    def run(self, **kwargs: Any) -> str:
        prompt = self.template.format(**kwargs)
        response = self.client.chat([{"role": "user", "content": prompt}])
        return response.content or ""

    def __call__(self, **kwargs: Any) -> str:
        return self.run(**kwargs)


class SequentialChain:
    """Chain multiple steps where each step's output feeds into the next."""

    def __init__(self, steps: list[Chain], pass_key: str = "input"):
        self.steps = steps
        self.pass_key = pass_key

    def run(self, **kwargs: Any) -> dict[str, str]:
        results: dict[str, str] = {}
        current_input = kwargs.get(self.pass_key, "")

        for i, step in enumerate(self.steps):
            step_kwargs = {**kwargs, self.pass_key: current_input}
            output = step.run(**step_kwargs)
            results[step.output_key] = output
            current_input = output

        results["final"] = current_input
        return results


class StructuredChain(Chain):
    """Chain that returns structured Pydantic model output."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        template: str | PromptTemplate,
        output_model: type[T],
    ):
        super().__init__(client, template, output_key=output_model.__name__)
        self.output_model = output_model

    def run(self, **kwargs: Any) -> T:
        schema = self.output_model.model_json_schema()
        prompt = self.template.format(**kwargs)
        prompt += f"\n\nRespond with valid JSON matching this schema:\n{schema}"

        data = self.client.chat_json([{"role": "user", "content": prompt}])
        return self.output_model.model_validate(data)
