"""Chain implementations for DevAI."""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClientProtocol
from devai.core.models import Message
from devai.output.parser import parse_model
from devai.prompts.templates import PromptTemplate

T = TypeVar("T", bound=BaseModel)


class SimpleChain:
    """A simple prompt → LLM → output chain."""

    def __init__(
        self,
        client: LLMClientProtocol,
        prompt: PromptTemplate,
        system_override: str | None = None,
    ) -> None:
        self.client = client
        self.prompt = prompt
        self.system_override = system_override

    def run(self, **kwargs: Any) -> str:
        messages = []
        system = self.system_override or self.prompt.system
        if system:
            messages.append(Message.system(system))
        messages.append(Message.user(self.prompt.format(**kwargs)))
        return self.client.complete(messages)


class SequentialChain:
    """Chain multiple steps where each output feeds into the next."""

    def __init__(self, client: LLMClientProtocol) -> None:
        self.client = client
        self.steps: list[tuple[PromptTemplate, str]] = []

    def add_step(self, prompt: PromptTemplate, output_key: str) -> SequentialChain:
        self.steps.append((prompt, output_key))
        return self

    def run(self, **kwargs: Any) -> dict[str, str]:
        context = dict(kwargs)
        results: dict[str, str] = {}

        for prompt, output_key in self.steps:
            merged = {**context, **{k: v for k, v in results.items()}}
            chain = SimpleChain(self.client, prompt)
            result = chain.run(**merged)
            results[output_key] = result
            context[output_key] = result

        return results


class StructuredChain:
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        client: LLMClientProtocol,
        prompt: PromptTemplate,
        output_model: type[T],
    ) -> None:
        self.client = client
        self.prompt = prompt
        self.output_model = output_model
        self._simple = SimpleChain(client, prompt)

    def run(self, **kwargs: Any) -> T:
        raw = self._simple.run(**kwargs)
        return parse_model(raw, self.output_model)

    async def arun(self, **kwargs: Any) -> T:
        messages = []
        if self.prompt.system:
            messages.append(Message.system(self.prompt.system))
        messages.append(Message.user(self.prompt.format(**kwargs)))
        raw = await self.client.acomplete(messages, json_mode=True)
        return parse_model(raw, self.output_model)
