"""Composable LLM chains."""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role

T = TypeVar("T", bound=BaseModel)


class SimpleChain:
    """A single-prompt chain that sends input to an LLM."""

    def __init__(self, client: LLMClient | MockLLMClient, prompt_template: str) -> None:
        self.client = client
        self.prompt_template = prompt_template

    def run(self, **kwargs: str) -> str:
        prompt = self.prompt_template.format(**kwargs) if "{" in self.prompt_template else self.prompt_template
        for key, val in kwargs.items():
            prompt = prompt.replace(f"${key}", val)
        messages = [Message(role=Role.USER, content=prompt)]
        return self.client.complete(messages).content


class SequentialChain:
    """Chain multiple steps where each output feeds the next."""

    def __init__(self, client: LLMClient | MockLLMClient, steps: list[tuple[str, str]]) -> None:
        self.client = client
        self.steps = steps

    def run(self, initial_input: str) -> str:
        current = initial_input
        for system_msg, user_template in self.steps:
            user_content = user_template.replace("{input}", current)
            messages = [
                Message(role=Role.SYSTEM, content=system_msg),
                Message(role=Role.USER, content=user_content),
            ]
            current = self.client.complete(messages).content
        return current


class StructuredChain:
    """Chain that returns validated Pydantic models."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        prompt: str,
        output_model: type[T],
    ) -> None:
        self.client = client
        self.prompt = prompt
        self.output_model = output_model

    def run(self, **kwargs: str) -> T:
        from devai.output import parse_model

        prompt = self.prompt
        for key, val in kwargs.items():
            prompt = prompt.replace(f"${key}", val)
        messages = [
            Message(role=Role.SYSTEM, content=f"Respond with JSON matching this schema: {self.output_model.model_json_schema()}"),
            Message(role=Role.USER, content=prompt),
        ]
        response = self.client.complete(messages, json_mode=True)
        return parse_model(response.content, self.output_model)
