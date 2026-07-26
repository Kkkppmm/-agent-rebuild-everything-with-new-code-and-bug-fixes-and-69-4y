"""Chain abstractions for composing LLM workflows."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel

from devai.core.models import Message, Role


class LLMProtocol(Protocol):
    def complete(self, messages: list[Message], **kwargs: Any) -> Message: ...


class Chain:
    """Single-step LLM chain: prompt template → LLM → output."""

    def __init__(
        self,
        llm: LLMProtocol,
        prompt: str,
        system: str = "You are a helpful assistant.",
    ) -> None:
        self.llm = llm
        self.prompt = prompt
        self.system = system

    def run(self, **kwargs: Any) -> str:
        user_content = self.prompt.format(**kwargs) if kwargs else self.prompt
        messages = [
            Message(role=Role.SYSTEM, content=self.system),
            Message(role=Role.USER, content=user_content),
        ]
        return self.llm.complete(messages).content


class SequentialChain:
    """Run multiple chains in sequence, passing output forward."""

    def __init__(self, chains: list[Chain]) -> None:
        self.chains = chains

    def run(self, **kwargs: Any) -> str:
        result = ""
        for i, chain in enumerate(self.chains):
            step_kwargs = {**kwargs}
            if i > 0:
                step_kwargs["previous_output"] = result
            result = chain.run(**step_kwargs)
        return result


class StructuredChain:
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        llm: LLMProtocol,
        prompt: str,
        output_model: type[BaseModel],
        system: str = "You are a helpful assistant. Respond in valid JSON.",
    ) -> None:
        self.chain = Chain(llm, prompt, system)
        self.output_model = output_model

    def run(self, **kwargs: Any) -> BaseModel:
        from devai.output.parser import parse_model

        raw = self.chain.run(**kwargs)
        return parse_model(raw, self.output_model)
