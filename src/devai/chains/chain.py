"""Chain abstractions for composing LLM workflows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.output.parser import StructuredParser

T = TypeVar("T", bound=BaseModel)


class Chain(ABC):
    """Base chain that transforms input to output."""

    @abstractmethod
    def run(self, input_data: str) -> str:
        ...


class LLMChain(Chain):
    """Simple prompt → LLM → response chain."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        prompt_template: str,
        system_prompt: str = "You are a helpful assistant.",
    ) -> None:
        self.client = client
        self.prompt_template = prompt_template
        self.system_prompt = system_prompt

    def run(self, input_data: str) -> str:
        messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(role=Role.USER, content=self.prompt_template.format(input=input_data)),
        ]
        return self.client.complete(messages).content


class SequentialChain(Chain):
    """Run multiple chains in sequence, passing output to next."""

    def __init__(self, chains: list[Chain]) -> None:
        self.chains = chains

    def run(self, input_data: str) -> str:
        result = input_data
        for chain in self.chains:
            result = chain.run(result)
        return result


class StructuredChain(Generic[T]):
    """Chain that returns a validated Pydantic model."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        prompt_template: str,
        output_model: type[T],
        system_prompt: str = "Respond with valid JSON matching the requested schema.",
    ) -> None:
        self.client = client
        self.prompt_template = prompt_template
        self.output_model = output_model
        self.system_prompt = system_prompt
        self.parser = StructuredParser(output_model)

    def run(self, **kwargs: Any) -> T:
        schema = self.output_model.model_json_schema()
        prompt = (
            f"{self.prompt_template.format(**kwargs)}\n\n"
            f"Respond with JSON matching this schema:\n{schema}"
        )
        messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(role=Role.USER, content=prompt),
        ]
        data = self.client.complete_json(messages)
        return self.parser.parse(data)
