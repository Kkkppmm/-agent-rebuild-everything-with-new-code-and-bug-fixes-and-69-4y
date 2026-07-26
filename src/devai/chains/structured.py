"""Structured output chain with Pydantic models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient
from devai.core.messages import Message
from devai.output.parser import parse_model

T = TypeVar("T", bound=BaseModel)


@dataclass
class StructuredChain:
    """Chain that returns parsed Pydantic model output."""

    client: LLMClient
    output_model: type[T]
    prompt_template: str
    system_message: str | None = None

    def run(self, **kwargs: str) -> T:
        prompt = self.prompt_template.format(**kwargs)
        schema_hint = f"\n\nRespond with valid JSON matching this schema:\n{self.output_model.model_json_schema()}"
        messages: list[Message] = []
        if self.system_message:
            messages.append(Message.system(self.system_message))
        messages.append(Message.user(prompt + schema_hint))
        response = self.client.complete(messages, json_mode=True)
        return parse_model(response.content, self.output_model)

    async def arun(self, **kwargs: str) -> T:
        prompt = self.prompt_template.format(**kwargs)
        schema_hint = f"\n\nRespond with valid JSON matching this schema:\n{self.output_model.model_json_schema()}"
        messages: list[Message] = []
        if self.system_message:
            messages.append(Message.system(self.system_message))
        messages.append(Message.user(prompt + schema_hint))
        response = await self.client.acomplete(messages, json_mode=True)
        return parse_model(response.content, self.output_model)
