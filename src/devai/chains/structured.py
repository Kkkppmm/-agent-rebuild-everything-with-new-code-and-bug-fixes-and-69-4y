"""Structured chain with Pydantic output parsing."""

from typing import Any, Type, TypeVar

from pydantic import BaseModel

from devai.chains.chain import Chain, LLMProtocol
from devai.core.models import Message, Role
from devai.output.parser import parse_model

T = TypeVar("T", bound=BaseModel)


class StructuredChain:
    """Chain that returns a validated Pydantic model."""

    def __init__(
        self,
        client: LLMProtocol,
        output_model: Type[T],
        prompt: str,
        system_prompt: str = "Respond with valid JSON matching the requested schema.",
    ) -> None:
        self.client = client
        self.output_model = output_model
        self.prompt = prompt
        self.system_prompt = system_prompt

    def run(self, **kwargs: Any) -> T:
        formatted = self.prompt.format(**kwargs) if "{" in self.prompt else self.prompt
        schema_hint = self.output_model.model_json_schema()
        messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(
                role=Role.USER,
                content=f"{formatted}\n\nRespond with JSON matching: {schema_hint}",
            ),
        ]
        response = self.client.complete(messages, json_mode=True)
        return parse_model(response.content, self.output_model)
