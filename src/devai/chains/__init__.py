"""Chain abstractions for composing LLM workflows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.output import parse_json, parse_model

T = TypeVar("T", bound=BaseModel)


class Chain(ABC):
    """Abstract base for LLM chains."""

    def __init__(self, client: LLMClient | MockLLMClient):
        self.client = client

    @abstractmethod
    def run(self, input_text: str, **kwargs: Any) -> Any:
        ...


class SimpleChain(Chain):
    """A chain with a system prompt and user input."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        system_prompt: str = "",
        temperature: float | None = None,
    ):
        super().__init__(client)
        self.system_prompt = system_prompt
        self.temperature = temperature

    def run(self, input_text: str, **kwargs: Any) -> str:
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message(role=Role.SYSTEM, content=self.system_prompt))
        messages.append(Message(role=Role.USER, content=input_text))
        response = self.client.chat(messages, temperature=self.temperature, **kwargs)
        return response.content


class SequentialChain:
    """Run multiple chains in sequence, passing output to the next."""

    def __init__(self, chains: list[Chain]):
        self.chains = chains

    def run(self, input_text: str, **kwargs: Any) -> Any:
        result = input_text
        for chain in self.chains:
            result = chain.run(str(result), **kwargs)
        return result


class StructuredChain(Chain, Generic[T]):
    """Chain that returns structured Pydantic output."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        output_model: type[T],
        system_prompt: str = "",
    ):
        super().__init__(client)
        self.output_model = output_model
        self.system_prompt = system_prompt

    def run(self, input_text: str, **kwargs: Any) -> T:
        schema = self.output_model.model_json_schema()
        prompt = (
            f"{input_text}\n\n"
            f"Respond with valid JSON matching this schema:\n{schema}"
        )
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message(role=Role.SYSTEM, content=self.system_prompt))
        messages.append(Message(role=Role.USER, content=prompt))

        response = self.client.chat(messages, json_mode=True, **kwargs)
        return parse_model(response.content, self.output_model)
