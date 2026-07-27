"""Chain implementations for DevAI."""

from typing import Any, Type

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import LLMResponse
from devai.prompts.template import PromptTemplate


class SimpleChain:
    """A single prompt → LLM → response chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        template: str | PromptTemplate,
        system: str | None = None,
    ) -> None:
        self.client = client
        self.template = (
            template if isinstance(template, PromptTemplate) else PromptTemplate(template)
        )
        self.system = system

    def run(self, **kwargs: Any) -> str:
        prompt = self.template.format(**kwargs)
        response = self.client.complete(prompt, system=self.system)
        return response.content


class SequentialChain:
    """Chain multiple steps where each output feeds into the next."""

    def __init__(self, steps: list[SimpleChain]) -> None:
        self.steps = steps

    def run(self, **kwargs: Any) -> list[str]:
        results: list[str] = []
        context = dict(kwargs)
        for step in self.steps:
            result = step.run(**context)
            results.append(result)
            context["previous_output"] = result
        return results


class StructuredChain:
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        template: str | PromptTemplate,
        output_model: Type[BaseModel],
        system: str | None = None,
    ) -> None:
        self.client = client
        self.template = (
            template if isinstance(template, PromptTemplate) else PromptTemplate(template)
        )
        self.output_model = output_model
        self.system = system or (
            f"Respond with valid JSON matching this schema: "
            f"{output_model.model_json_schema()}"
        )

    def run(self, **kwargs: Any) -> BaseModel:
        prompt = self.template.format(**kwargs)
        response = self.client.complete(
            prompt, system=self.system, json_mode=True,
        )
        return self.output_model.model_validate_json(response.content)
