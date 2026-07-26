"""Chain abstractions for composing LLM workflows."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.output import parse_model

T = TypeVar("T", bound=BaseModel)


class SimpleChain:
    """Single-prompt chain that returns raw text."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        config: DevAIConfig | None = None,
        *,
        prompt: str,
        system: str | None = None,
    ) -> None:
        self.client = client
        self.config = config or DevAIConfig()
        self.prompt = prompt
        self.system = system

    def run(self, **kwargs: str) -> str:
        formatted = self.prompt.format(**kwargs)
        return self.client.chat(formatted, system=self.system)


class SequentialChain:
    """Chain where each step's output feeds into the next."""

    def __init__(self, steps: list[SimpleChain]) -> None:
        self.steps = steps

    def run(self, **kwargs: str) -> str:
        context = dict(kwargs)
        result = ""
        for step in self.steps:
            merged = {**context, **kwargs}
            result = step.run(**merged)
            context["previous_output"] = result
        return result


class StructuredChain(Generic[T]):
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        config: DevAIConfig | None = None,
        *,
        prompt: str,
        output_model: type[T],
        system: str | None = None,
    ) -> None:
        self.client = client
        self.config = config or DevAIConfig()
        self.prompt = prompt
        self.output_model = output_model
        schema = output_model.model_json_schema()
        self.system = system or f"Respond with valid JSON matching: {schema}"

    def run(self, **kwargs: Any) -> T:
        formatted = self.prompt.format(**kwargs)
        raw = self.client.chat(formatted, system=self.system, json_mode=True)
        return parse_model(raw, self.output_model)
