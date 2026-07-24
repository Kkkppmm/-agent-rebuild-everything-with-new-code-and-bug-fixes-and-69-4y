"""Chain abstractions for composing LLM workflows."""

from __future__ import annotations

import json
from typing import Any, Protocol

from pydantic import BaseModel

from devai.core.models import Message, Role
from devai.output.parser import StructuredParser


class LLMProtocol(Protocol):
    def chat(self, messages: list[Message], **kwargs: Any) -> Message: ...
    def complete(self, prompt: str, **kwargs: Any) -> str: ...


class Chain:
    """A single-step LLM chain: prompt template → LLM → output."""

    def __init__(
        self,
        llm: LLMProtocol,
        prompt: str,
        *,
        system: str | None = None,
        output_key: str = "output",
    ) -> None:
        self.llm = llm
        self.prompt = prompt
        self.system = system
        self.output_key = output_key

    def run(self, **inputs: Any) -> dict[str, Any]:
        formatted = self.prompt.format(**inputs)
        result = self.llm.complete(formatted, system=self.system)
        return {self.output_key: result, **inputs}


class SequentialChain:
    """Run multiple chains in sequence, passing outputs forward."""

    def __init__(self, chains: list[Chain], *, final_key: str = "output") -> None:
        self.chains = chains
        self.final_key = final_key

    def run(self, **inputs: Any) -> dict[str, Any]:
        state = dict(inputs)
        for chain in self.chains:
            result = chain.run(**state)
            state.update(result)
        return state


class StructuredChain:
    """Chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        llm: LLMProtocol,
        prompt: str,
        output_model: type[BaseModel],
        *,
        system: str | None = None,
    ) -> None:
        self.llm = llm
        self.prompt = prompt
        self.output_model = output_model
        self.system = system
        self.parser = StructuredParser(output_model)

    def run(self, **inputs: Any) -> BaseModel:
        formatted = self.prompt.format(**inputs)
        sys = (self.system or "") + "\nRespond with valid JSON only."
        messages = []
        if sys:
            messages.append(Message(role=Role.SYSTEM, content=sys))
        messages.append(Message(role=Role.USER, content=formatted))
        response = self.llm.chat(messages, json_mode=True)
        return self.parser.parse(response.content)
