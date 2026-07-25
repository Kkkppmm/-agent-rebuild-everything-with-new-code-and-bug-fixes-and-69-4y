"""Composable LLM chains."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from devai.core.client import LLMClient
from devai.core.models import Message
from devai.prompts.template import PromptTemplate


class Chain:
  """Pipeline that transforms input through prompt templates and LLM calls."""

  def __init__(
    self,
    client: LLMClient,
    template: PromptTemplate,
    *,
    output_key: str = "result",
  ) -> None:
    self.client = client
    self.template = template
    self.output_key = output_key

  def run(self, **variables: Any) -> dict[str, Any]:
    """Execute the chain synchronously."""
    messages = self.template.to_messages(**variables)
    result = self.client.complete(messages)
    return {self.output_key: result.content or "", "usage": result.usage}

  async def arun(self, **variables: Any) -> dict[str, Any]:
    """Execute the chain asynchronously."""
    messages = self.template.to_messages(**variables)
    result = await self.client.acomplete(messages)
    return {self.output_key: result.content or "", "usage": result.usage}

  def pipe(self, transform: Callable[[str], str]) -> Chain:
    """Return a new chain that post-processes the LLM output."""
    parent = self

    class TransformedChain(Chain):
      def run(self, **variables: Any) -> dict[str, Any]:
        output = super().run(**variables)
        output[parent.output_key] = transform(output[parent.output_key])
        return output

      async def arun(self, **variables: Any) -> dict[str, Any]:
        output = await super().arun(**variables)
        output[parent.output_key] = transform(output[parent.output_key])
        return output

    return TransformedChain(parent.client, parent.template, output_key=parent.output_key)

  @classmethod
  def from_system_user(
    cls,
    client: LLMClient,
    system: str,
    user: str,
    **kwargs: Any,
  ) -> Chain:
    """Quick factory for a system + user prompt chain."""
    template = PromptTemplate(user, system=system)
    return cls(client, template, **kwargs)

  def as_messages(self, **variables: Any) -> list[Message]:
    """Preview the messages that would be sent."""
    return self.template.to_messages(**variables)

  def __repr__(self) -> str:
    return f"Chain(output_key={self.output_key!r})"
