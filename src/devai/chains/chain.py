"""Chain abstractions for DevAI."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel

from devai.core.models import Message
from devai.output.parser import StructuredParser, parse_model


class LLMProtocol(Protocol):
    def chat(self, messages: list[Message], **kwargs: Any) -> Any: ...


class Chain:
    """A prompt-to-response chain backed by an LLM."""

    def __init__(
        self,
        llm: LLMProtocol,
        system_prompt: str = "You are a helpful programming assistant.",
    ):
        self.llm = llm
        self.system_prompt = system_prompt

    def run(self, prompt: str, **kwargs: Any) -> str:
        messages = [
            Message.system(self.system_prompt),
            Message.user(prompt),
        ]
        response = self.llm.chat(messages, **kwargs)
        return response.content or ""

    async def arun(self, prompt: str, **kwargs: Any) -> str:
        if hasattr(self.llm, "achat"):
            messages = [
                Message.system(self.system_prompt),
                Message.user(prompt),
            ]
            response = await self.llm.achat(messages, **kwargs)
            return response.content or ""
        return self.run(prompt, **kwargs)


class SequentialChain:
    """Run multiple chains in sequence, passing output forward."""

    def __init__(self, steps: list[tuple[str, Chain]]):
        self.steps = steps

    def run(self, initial_input: str, **kwargs: Any) -> dict[str, str]:
        results: dict[str, str] = {}
        current = initial_input
        for name, chain in self.steps:
            current = chain.run(current, **kwargs)
            results[name] = current
        return results


class StructuredChain(Chain):
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        llm: LLMProtocol,
        output_model: type[BaseModel],
        system_prompt: str = "You are a helpful assistant. Respond with valid JSON only.",
    ):
        super().__init__(llm, system_prompt)
        self.output_model = output_model
        self.parser = StructuredParser(output_model)

    def run(self, prompt: str, **kwargs: Any) -> BaseModel:
        kwargs.setdefault("json_mode", True)
        raw = super().run(prompt, **kwargs)
        return parse_model(raw, self.output_model)
