"""Composable prompt chains."""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.output.parser import StructuredParser

T = TypeVar("T", bound=BaseModel)


class SimpleChain:
  """A single-prompt chain that sends input to an LLM."""

  def __init__(
    self,
    client: LLMClient | MockLLMClient,
    prompt_template: str,
    system: str | None = None,
  ) -> None:
    self.client = client
    self.prompt_template = prompt_template
    self.system = system

  def run(self, **kwargs: str) -> str:
    prompt = self.prompt_template.format(**kwargs)
    messages: list[Message] = []
    if self.system:
      messages.append(Message(role=Role.SYSTEM, content=self.system))
    messages.append(Message(role=Role.USER, content=prompt))
    return self.client.complete(messages).content


class SequentialChain:
  """Chain multiple steps where each output feeds the next."""

  def __init__(self, steps: list[SimpleChain]) -> None:
    self.steps = steps

  def run(self, **kwargs: str) -> list[str]:
    results: list[str] = []
    context = dict(kwargs)
    for step in self.steps:
      output = step.run(**context)
      results.append(output)
      context["previous_output"] = output
    return results


class StructuredChain:
  """Chain that parses LLM output into a Pydantic model."""

  def __init__(
    self,
    client: LLMClient | MockLLMClient,
    prompt_template: str,
    output_model: type[T],
    system: str | None = None,
  ) -> None:
    self.client = client
    self.prompt_template = prompt_template
    self.output_model = output_model
    self.system = system
    self.parser = StructuredParser(output_model)

  def run(self, **kwargs: str) -> T:
    prompt = self.prompt_template.format(**kwargs)
    prompt += f"\n\nRespond with valid JSON matching this schema:\n{self.output_model.model_json_schema()}"
    messages: list[Message] = []
    if self.system:
      messages.append(Message(role=Role.SYSTEM, content=self.system))
    messages.append(Message(role=Role.USER, content=prompt))
    result = self.client.complete(messages, json_mode=True)
    return self.parser.parse(result.content)
