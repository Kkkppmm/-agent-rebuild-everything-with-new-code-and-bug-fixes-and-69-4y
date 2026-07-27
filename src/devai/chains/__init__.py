"""Composable prompt chains."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel

from devai.core.models import Message, Role
from devai.output import parse_model


class LLMProtocol(Protocol):
  def complete(self, messages: list[Message], **kwargs: Any) -> Any: ...


class SimpleChain:
  """Single-prompt chain that calls an LLM."""

  def __init__(self, client: LLMProtocol, system: str = "", **default_kwargs: Any) -> None:
    self.client = client
    self.system = system
    self.default_kwargs = default_kwargs

  def run(self, prompt: str, **kwargs: Any) -> str:
    messages: list[Message] = []
    if self.system:
      messages.append(Message(role=Role.SYSTEM, content=self.system))
    messages.append(Message(role=Role.USER, content=prompt))
    merged = {**self.default_kwargs, **kwargs}
    result = self.client.complete(messages, **merged)
    return result.content if hasattr(result, "content") else str(result)


class SequentialChain:
  """Chain where each step's output feeds the next."""

  def __init__(self, client: LLMProtocol, steps: list[str], system: str = "") -> None:
    self.client = client
    self.steps = steps
    self.system = system

  def run(self, initial_input: str, **kwargs: Any) -> str:
    context = initial_input
    for step in self.steps:
      prompt = step.replace("{input}", context)
      chain = SimpleChain(self.client, system=self.system, **kwargs)
      context = chain.run(prompt)
    return context


class StructuredChain:
  """Chain that returns structured Pydantic output."""

  def __init__(self, client: LLMProtocol, model: type[BaseModel], system: str = "") -> None:
    self.client = client
    self.model = model
    self.system = system

  def run(self, prompt: str, **kwargs: Any) -> BaseModel:
    schema_hint = f"\n\nRespond with valid JSON matching this schema:\n{self.model.model_json_schema()}"
    chain = SimpleChain(self.client, system=self.system, json_mode=True, **kwargs)
    raw = chain.run(prompt + schema_hint)
    return parse_model(raw, self.model)
