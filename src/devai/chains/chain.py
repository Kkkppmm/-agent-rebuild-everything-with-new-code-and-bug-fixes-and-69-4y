"""Chain for composing prompt + LLM pipelines."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts.template import PromptTemplate


class Chain:
  """A simple pipeline: template → LLM → optional post-processor."""

  def __init__(
    self,
    template: PromptTemplate | str,
    client: LLMClient | None = None,
    *,
    system_prompt: str = "You are a helpful programming assistant.",
    post_process: Callable[[str], Any] | None = None,
  ) -> None:
    if isinstance(template, str):
      template = PromptTemplate(template)
    self.template = template
    self.client = client or LLMClient()
    self.system_prompt = system_prompt
    self.post_process = post_process

  def run(self, **variables: Any) -> str | Any:
    """Execute the chain with template variables."""
    prompt = self.template.format(**variables)
    messages = [
      Message.system(self.system_prompt),
      Message.user(prompt),
    ]
    response = self.client.chat(messages)
    result = response.content
    if self.post_process:
      return self.post_process(result)
    return result

  async def arun(self, **variables: Any) -> str | Any:
    """Async version of run."""
    prompt = self.template.format(**variables)
    messages = [
      Message.system(self.system_prompt),
      Message.user(prompt),
    ]
    response = await self.client.achat(messages)
    result = response.content
    if self.post_process:
      return self.post_process(result)
    return result

  @classmethod
  def from_config(cls, template: PromptTemplate | str, config: DevAIConfig) -> Chain:
    return cls(template, LLMClient(config))
