"""Composable prompt chains."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.output.parser import parse_model

T = TypeVar("T", bound=BaseModel)


class SimpleChain:
    """A single prompt → LLM → response chain."""

    def __init__(
        self,
        prompt_template: Callable[..., str],
        config: DevAIConfig | None = None,
        client: LLMClient | None = None,
        system: str = "You are a helpful assistant.",
    ) -> None:
        self.prompt_template = prompt_template
        self.config = config or DevAIConfig.from_env()
        if client:
            self.client = client
        elif self.config.api_key == "mock-key":
            self.client = MockLLMClient(self.config)
        else:
            self.client = LLMClient(self.config)
        self.system = system

    def run(self, **kwargs: Any) -> str:
        prompt = self.prompt_template(**kwargs)
        messages = [Message.system(self.system), Message.user(prompt)]
        response = self.client.complete(messages)
        return response.content or ""


class SequentialChain:
    """Chain multiple steps where each step's output feeds the next."""

    def __init__(self, steps: list[SimpleChain]) -> None:
        self.steps = steps

    def run(self, **kwargs: Any) -> str:
        result = ""
        for i, step in enumerate(self.steps):
            step_kwargs = dict(kwargs)
            if i > 0:
                step_kwargs["previous_output"] = result
            result = step.run(**step_kwargs)
        return result


class StructuredChain(SimpleChain):
    """Chain that parses output into a Pydantic model."""

    def __init__(
        self,
        prompt_template: Callable[..., str],
        output_model: type[T],
        config: DevAIConfig | None = None,
        client: LLMClient | None = None,
        system: str = "You are a helpful assistant. Respond in valid JSON.",
    ) -> None:
        super().__init__(prompt_template, config=config, client=client, system=system)
        self.output_model = output_model

    def run(self, **kwargs: Any) -> T:
        text = super().run(**kwargs)
        return parse_model(text, self.output_model)
