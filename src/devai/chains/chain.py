"""Chain abstractions for composing LLM workflows."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.output.parser import StructuredParser

T = TypeVar("T", bound=BaseModel)


class Chain:
    """A single-step LLM chain with a prompt template function."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        prompt_fn: Callable[..., str],
        system: str = "You are a helpful assistant.",
    ) -> None:
        self.client = client
        self.prompt_fn = prompt_fn
        self.system = system

    def run(self, **kwargs: Any) -> str:
        prompt = self.prompt_fn(**kwargs)
        messages = [
            Message(role=Role.SYSTEM, content=self.system),
            Message(role=Role.USER, content=prompt),
        ]
        response = self.client.chat(messages)
        return response.content

    async def arun(self, **kwargs: Any) -> str:
        prompt = self.prompt_fn(**kwargs)
        messages = [
            Message(role=Role.SYSTEM, content=self.system),
            Message(role=Role.USER, content=prompt),
        ]
        response = await self.client.achat(messages)
        return response.content


class SequentialChain:
    """Run multiple chains in sequence, passing output forward."""

    def __init__(self, *steps: Chain) -> None:
        self.steps = steps

    def run(self, **kwargs: Any) -> str:
        context = dict(kwargs)
        result = ""
        for step in self.steps:
            result = step.run(**context)
            context["previous_output"] = result
        return result

    async def arun(self, **kwargs: Any) -> str:
        context = dict(kwargs)
        result = ""
        for step in self.steps:
            result = await step.arun(**context)
            context["previous_output"] = result
        return result


class StructuredChain(Chain):
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        prompt_fn: Callable[..., str],
        output_model: type[T],
        system: str = "You are a helpful assistant. Respond in valid JSON.",
    ) -> None:
        super().__init__(client, prompt_fn, system)
        self.output_model = output_model
        self.parser = StructuredParser(output_model)

    def run(self, **kwargs: Any) -> T:
        raw = super().run(**kwargs)
        return self.parser.parse(raw)

    async def arun(self, **kwargs: Any) -> T:
        raw = await super().arun(**kwargs)
        return self.parser.parse(raw)
